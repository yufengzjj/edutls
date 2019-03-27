import contextlib
import logging
import threading
import time
from asyncio import Future
from enum import IntEnum
import asyncio
import typing
from collections import deque
from edutls.types import switch
from edutls.record import TLSCiphertext, TLSPlaintext, ContentType
from edutls.handshake import IHandshake, ClientHello, ServerHello, Handshake, HandshakeType, EncryptedExtensions, \
    CertificateRequest, Certificate, CertificateVerify, Finished, EndOfEarlyData, NewSessionTicket
from edutls.extension import Extension, SupportedVersions, NamedGroupList, SignatureSchemeList, KeyShareEntry, \
    KeyShareClientHello, KeyShareServerHello, ExtensionType, PskIdentity, PskBinderEntry, OfferedPsks, \
    PreSharedKeyExtension, SelectedIdentity, PskKeyExchangeModes, EarlyDataIndication, ServerNameList, ServerName, \
    KeyExchange, NamedGroup, PskKeyExchangeMode
from edutls.keys import KeyDerivation
from edutls.alert import Alert


class TLSClientMachineState(IntEnum):
    SHUTDOWN = -2,
    INIT = -1,
    START = 0,
    WAIT_SH = 1,
    WAIT_EE = 2,
    WAIT_CERT_CR = 3,
    WAIT_CERT = 4,
    WAIT_CV = 5,
    WAIT_FINISHED = 6,
    END_EARLY_DATA = 7,
    CONNECTED = 8


class TLSClientMachine(asyncio.Protocol):
    def __init__(self):
        self.transport: asyncio.transports.Transport = None
        self.loop: asyncio.AbstractEventLoop = None
        self.state = TLSClientMachineState.INIT
        self.handshakes: typing.List[Handshake] = []
        self._data_recv_internal: typing.Deque[bytes] = deque()
        self._user_recv_data: typing.Deque[bytes] = deque()
        self._user_write_data: typing.Deque[bytes] = deque()
        self.key: KeyDerivation = None
        self._read_engine_thread = threading.Thread(target=self._read_engine)
        self._write_engine_thread = threading.Thread(target=self._write_engine)
        self._need_read_data_event = threading.Event()
        self._need_write_data_event = threading.Event()
        self._on_con_lost: Future = None
        self._new_session_tickets: typing.List[NewSessionTicket] = []
        self._use_psk = False
        self.host_port: typing.Tuple[bytes, int] = None

        # log in debug
        logging.basicConfig(
            format="[%(asctime)s] [%(name)s] [%(levelname)s] [%(filename)s:%(funcName)s:%(lineno)d] %(message)s")
        self.logger = logging.getLogger("TLS Client")
        self.logger.setLevel(logging.DEBUG)

    def process_record(self, record: TLSPlaintext):
        self.logger.debug(f"receive {record.content_type.name} record")
        for case in switch(record.content_type):
            if case(ContentType.invalid):
                self.state = TLSClientMachineState.SHUTDOWN
                break
            if case(ContentType.alert):
                alert = Alert()
                alert.unpack(record.data)
                self.logger.warning(f"receive alert:{alert.description.name}")
                break
            if case(ContentType.handshake):
                handshake = Handshake()
                handshake.unpack(record.data)
                self._process_handshake(handshake)
                break
            if case(ContentType.application_data):
                self._user_recv_data.appendleft(record.data)
                break
            if case(ContentType.change_cipher_spec):
                break
            if case():
                self.logger.warning(f"unsupported record type:{record.content_type.name}")
                self.state = TLSClientMachineState.SHUTDOWN
                break

    def _process_handshake(self, handshake: Handshake):
        self.logger.debug(f"receive {handshake.handshake_type.name} handshake")
        for case in switch(handshake.handshake_type):
            if case(HandshakeType.server_hello):
                server_hello = ServerHello()
                with contextlib.suppress(Exception):
                    server_hello.unpack(handshake.handshake_data)
                if server_hello.is_retry() is True:
                    print(f"HelloRetry received, unable to continue. "
                          f"server select support version:{server_hello.selected_version} "
                          f"cipher suite:{server_hello.selected_cipher_suite} "
                          f" support_group:{server_hello.selected_supported_group}")
                    self.state = TLSClientMachineState.SHUTDOWN
                    break
                assert self.state == TLSClientMachineState.WAIT_SH, f"unexpected server_hello under state:{self.state.name}"
                handshake.handshake = server_hello
                self.handshakes.append(handshake)
                self._derive_keys(server_hello)
                self.state = TLSClientMachineState.WAIT_EE
                self._send_early_data()
                break
            if case(HandshakeType.encrypted_extensions):
                assert self.state == TLSClientMachineState.WAIT_EE, f"unexpected encrypted_extensions under state:{self.state.name}"
                encrypted_extensions = EncryptedExtensions()
                encrypted_extensions.unpack(handshake.handshake_data)
                handshake.handshake = encrypted_extensions
                self.handshakes.append(handshake)
                if self.key.use_psk():
                    self.state = TLSClientMachineState.WAIT_FINISHED
                else:
                    self.state = TLSClientMachineState.WAIT_CERT_CR
                break
            if case(HandshakeType.certificate_request):
                assert self.state == TLSClientMachineState.WAIT_CERT_CR, \
                    f"unexpected certificate_request under state:{self.state.name}"
                certificate_request = CertificateRequest()
                certificate_request.unpack(handshake.handshake_data)
                handshake.handshake = certificate_request
                self.handshakes.append(handshake)
                self.state = TLSClientMachineState.WAIT_CERT
                break
            if case(HandshakeType.certificate):
                assert self.state in (
                    TLSClientMachineState.WAIT_CERT_CR,
                    TLSClientMachineState.WAIT_CERT), f"unexpected certificate_request under state:{self.state.name}"
                certificate = Certificate()
                certificate.unpack(handshake.handshake_data)
                handshake.handshake = certificate
                self.handshakes.append(handshake)
                self.state = TLSClientMachineState.WAIT_CV
                break
            if case(HandshakeType.certificate_verify):
                assert self.state == TLSClientMachineState.WAIT_CV, f"unexpected certificate_verify under state:{self.state.name}"
                certificate_verify = CertificateVerify()
                certificate_verify.unpack(handshake.handshake_data)
                handshake.handshake = certificate_verify
                self.handshakes.append(handshake)
                self.state = TLSClientMachineState.WAIT_FINISHED
                break
            if case(HandshakeType.finished):
                assert self.state == TLSClientMachineState.WAIT_FINISHED, f"unexpected finished under state:{self.state.name}"
                finished = Finished()
                finished.unpack(handshake.handshake_data)
                verify_data = self.key.hmac_verify(self.key.server_handshake_finished_key(self._handshake_secret_ctx()),
                                                   tuple(self.handshakes))
                assert verify_data == finished.verify_data, f"finished verify failed!"
                handshake.handshake = finished
                self.handshakes.append(handshake)
                self._reach_end_of_early_data()
                self.state = TLSClientMachineState.END_EARLY_DATA
                self._post_certificate()
                self._post_certificate_verify()
                self._finished()
                self.state = TLSClientMachineState.CONNECTED
                self._new_session_tickets.clear()
                self._write_engine_thread.start()
                break
            if case(HandshakeType.new_session_ticket):
                assert self.state == TLSClientMachineState.CONNECTED, f"unexpected new_session_ticket under state:{self.state.name}"
                new_session_ticket = NewSessionTicket()
                new_session_ticket.unpack(handshake.handshake_data)
                new_session_ticket.psk = self.key.resume_psk(new_session_ticket.ticket_nonce, self._resumption_ctx())
                self._new_session_tickets.append(new_session_ticket)
                break
            if case():
                self.logger.warning(f"there is unhandled handshake:{handshake.handshake_type.name}")
                break

    def _derive_keys(self, server_hello: ServerHello):
        """
        choose psk handshake otherwise use ECDHE
        note: if try psk, must use the machine derived from the ECDHE or other psk handshake
        :param server_hello:
        :return:
        """
        psk: bytes = None
        ecdhe: bytes = None
        for extension in server_hello.extensions:
            if extension.ext_type == ExtensionType.pre_shared_key:
                pre_share_key: PreSharedKeyExtension = extension.ext
                selected_identity: SelectedIdentity = pre_share_key.ext
                assert 0 < selected_identity.index < len(self._new_session_tickets), \
                    f"received error identity index:{selected_identity.index}"
                self._use_psk = True
                psk = self._new_session_tickets[selected_identity.index].psk
                self.logger.debug("using psk handshake")
        with contextlib.suppress(Exception):
            ecdhe: bytes = self._exchange_key(server_hello)
        assert not (ecdhe is None and psk is None), f"both psk and ecdhe are empty!"
        self.key = KeyDerivation(server_hello.cipher_suite, psk, ecdhe)
        self.logger.debug("using ecdhe handshake")

    def _exchange_key(self, server_hello: ServerHello) -> bytes:
        assert len(self.handshakes) > 0 and self.handshakes[0].handshake_type == HandshakeType.client_hello, \
            f"client_hello handshake not exists when key exchange"
        client_hello: ClientHello = self.handshakes[0].handshake
        server_key_share = None
        client_key_share = None
        for extension in server_hello.extensions:
            if extension.ext_type == ExtensionType.key_share:
                server_key_share: KeyShareServerHello = extension.ext
                break
        for extension in client_hello.extensions:
            if extension.ext_type == ExtensionType.key_share:
                client_key_share: KeyShareClientHello = extension.ext
                break
        assert client_key_share is not None, f"client key_share extension not exists"
        assert server_key_share is not None, f"server key_share extension not exists"
        for key_share in client_key_share.key_shares:
            if key_share.key_exchange.group == server_key_share.key_share.key_exchange.group:
                return key_share.key_exchange.exchange(server_key_share.key_share.key_exchange.public)
        assert False, f"no match key exchange group found"

    def _read_engine(self):
        buff = b""
        while self.state != TLSClientMachineState.SHUTDOWN or len(self._data_recv_internal) > 0:
            try:
                self._need_read_data_event.clear()
                if len(self._data_recv_internal) > 0:
                    buff += self._data_recv_internal.pop()
                record = TLSPlaintext()
                buff = record.unpack(buff)
                if record.content_type == ContentType.application_data and \
                        TLSClientMachineState.WAIT_SH < self.state <= TLSClientMachineState.CONNECTED:
                    c_record = self.construct_read_tls_cipher_text(record.content_type, record.data)
                    record = c_record.tls_inner_plaintext.to_tls_plaintext()
                self.process_record(record)
            except AssertionError as er:
                self.logger.error("%s", er)
                if len(self._data_recv_internal) <= 0:
                    self._need_read_data_event.wait()

    def _write_engine(self):
        while self.state != TLSClientMachineState.SHUTDOWN:
            if self.state == TLSClientMachineState.CONNECTED and len(self._user_write_data) > 0:
                self._need_write_data_event.clear()
                user_data = self._user_write_data.pop()
                self.write_application_data(user_data)
                continue
            if len(self._user_write_data) <= 0:
                self._need_write_data_event.wait()
            else:
                time.sleep(0.1)

    def _send_early_data(self):
        while TLSClientMachineState.WAIT_SH <= self.state < TLSClientMachineState.END_EARLY_DATA \
                and self._use_psk and len(self._user_write_data) > 0:
            user_data = self._user_write_data.pop()
            self.write_application_data(user_data)

    def _factory(self):
        return self

    async def connect(self, host: str, port: int):
        assert self.state == TLSClientMachineState.INIT, "connected already"
        self.host_port = (host.encode("utf-8"), port)
        self.state = TLSClientMachineState.START
        self.loop = asyncio.get_running_loop()
        self._on_con_lost = self.loop.create_future()
        transport, protocol = await self.loop.create_connection(self._factory, host, port)
        try:
            await self._on_con_lost
        finally:
            transport.close()

    def reset(self):
        assert self.state == TLSClientMachineState.SHUTDOWN, f"reset is not allowed under state:{self.state.name}"
        self._need_read_data_event.set()
        self._need_write_data_event.set()
        if self._read_engine_thread.is_alive():
            self._read_engine_thread.join()
        if self._write_engine_thread.is_alive():
            self._write_engine_thread.join()
        self._read_engine_thread = threading.Thread(target=self._read_engine)
        self._write_engine_thread = threading.Thread(target=self._write_engine)
        self._use_psk = False
        self.handshakes.clear()
        self.state = TLSClientMachineState.INIT

    def connection_made(self, transport: asyncio.transports.BaseTransport):
        self.transport: asyncio.transports.Transport = transport
        self._read_engine_thread.start()
        self._say_hello()

    def connection_lost(self, exc: typing.Optional[Exception]):
        self.state = TLSClientMachineState.SHUTDOWN
        self.logger.info("connection closed")
        self._on_con_lost.set_result(True)

    def data_received(self, data: bytes):
        self.logger.debug("receive %s bytes data", len(data))
        self._data_recv_internal.appendleft(data)
        self._need_read_data_event.set()

    def _say_hello(self):
        extensions = [Extension(SupportedVersions()), Extension(ServerNameList((ServerName(self.host_port[0]),))),
                      Extension(SignatureSchemeList()), Extension(NamedGroupList()),
                      Extension(KeyShareClientHello((KeyShareEntry(KeyExchange(NamedGroup.x25519)),
                                                     KeyShareEntry(KeyExchange(NamedGroup.secp256r1)),)
                                                    ))]
        if len(self._new_session_tickets) > 0 and self._new_session_tickets[0].max_early_data_size >= 0:
            if self._new_session_tickets[0].max_early_data_size <= 0:
                extensions.append(Extension(PskKeyExchangeModes((PskKeyExchangeMode.psk_dhe_ke,))))
            else:
                extensions.append(Extension(PskKeyExchangeModes((PskKeyExchangeMode.psk_ke,))))
            if len(self._user_write_data) > 0:
                extensions.append(EarlyDataIndication())
            hash_size: int = self.key.hash_digest_size()
            psk_num: int = len(self._new_session_tickets)
            identities: typing.List[PskIdentity] = []
            binders: typing.List[PskBinderEntry] = []
            for new_session_ticket in self._new_session_tickets:
                obfuscated_ticket_age = (new_session_ticket.ticket_lifetime * 1000 +
                                         new_session_ticket.ticket_age_add) % (2 ** 32)
                identities.append(PskIdentity(new_session_ticket.ticket, obfuscated_ticket_age))
                binders.append(PskBinderEntry(b"\x00" * hash_size))
            offered_psks = OfferedPsks(tuple(identities), tuple(binders))
            extensions.append(Extension(PreSharedKeyExtension(offered_psks)))
            client_hello = ClientHello(tuple(extensions))
            binders_size = psk_num * (hash_size + 1) + 2
            client_hello_data = client_hello.pack()[:-binders_size]
            binders.clear()
            for new_session_ticket in self._new_session_tickets:
                key = KeyDerivation(self.key.cipher_suite(), new_session_ticket.psk)
                finished_key = key.finished_key(key.res_binder_key())
                binders.append(PskBinderEntry(key.just_hmac_verify(finished_key, client_hello_data)))
            offered_psks = OfferedPsks(tuple(identities), tuple(binders))
            extensions[-1] = Extension(PreSharedKeyExtension(offered_psks))
        client_hello = ClientHello(tuple(extensions))
        self.write_plain_handshake(client_hello)
        self.state = TLSClientMachineState.WAIT_SH

    def construct_write_tls_cipher_text(self, content_type: ContentType,
                                        content: bytes) -> typing.Tuple[TLSCiphertext, ...]:
        plaintext = TLSPlaintext(content_type, content)
        tls_inner_plaintext = plaintext.to_tls_inner_plaintext()
        records = []
        for inner_plaintext in tls_inner_plaintext:
            if TLSClientMachineState.WAIT_SH <= self.state < TLSClientMachineState.END_EARLY_DATA and self._use_psk:
                record = TLSCiphertext(self.key.client_early_traffic_write_key(self._early_secret_ctx()),
                                       self.key.client_early_traffic_write_nonce(self._early_secret_ctx()),
                                       inner_plaintext)
            elif TLSClientMachineState.END_EARLY_DATA <= self.state < TLSClientMachineState.CONNECTED:
                record = TLSCiphertext(self.key.client_handshake_traffic_write_key(self._handshake_secret_ctx()),
                                       self.key.client_handshake_traffic_write_nonce(self._handshake_secret_ctx()),
                                       inner_plaintext)
            elif self.state == TLSClientMachineState.CONNECTED:
                record = TLSCiphertext(self.key.client_application_traffic_write_key(self._application_secret_ctx()),
                                       self.key.client_application_traffic_write_nonce(self._application_secret_ctx()),
                                       inner_plaintext)
            else:
                assert False, f"illegal state:{self.state.name} using TLSCiphertext"
            record.encrypt(self.key.record_protection_algorithm())
            records.append(record)
        return tuple(records)

    def construct_read_tls_cipher_text(self, content_type: ContentType, content: bytes) -> TLSCiphertext:
        if TLSClientMachineState.WAIT_SH < self.state < TLSClientMachineState.CONNECTED:
            record = TLSCiphertext(self.key.server_handshake_traffic_write_key(self._handshake_secret_ctx()),
                                   self.key.server_handshake_traffic_write_nonce(self._handshake_secret_ctx()))
        elif self.state == TLSClientMachineState.CONNECTED:
            record = TLSCiphertext(self.key.server_application_traffic_write_key(self._application_secret_ctx()),
                                   self.key.server_application_traffic_write_nonce(self._application_secret_ctx()))
        else:
            assert False, f"illegal state:{self.state.name} using TLSCiphertext"
        record.content_type = content_type
        record.encrypted_record = content
        record.decrypt(self.key.record_protection_algorithm())
        record.tls_inner_plaintext.unpack(record.encrypted_record)
        return record

    def write_protected_handshake(self, hs: IHandshake):
        handshake = Handshake(hs)
        self.handshakes.append(handshake)
        records = self.construct_write_tls_cipher_text(handshake.type, handshake.pack())
        records_data = b"".join((record.pack() for record in records))
        self.transport.write(records_data)
        self.logger.debug(f"write {len(records_data)} bytes handshake")

    def write_plain_handshake(self, hs: IHandshake):
        handshake = Handshake(hs)
        self.handshakes.append(handshake)
        record = TLSPlaintext(handshake.type, handshake.pack())
        record_data = record.pack()
        self.transport.write(record_data)
        self.logger.debug(f"write {len(record_data)} bytes handshake")

    def _reach_end_of_early_data(self):
        if not self._had_early_data():
            return
        end_of_early_data = EndOfEarlyData()
        self.write_protected_handshake(end_of_early_data)

    def _post_certificate(self):
        pass

    def _post_certificate_verify(self):
        pass

    def _finished(self):
        finished = Finished(self.key.hmac_verify(self.key.client_handshake_finished_key(self._handshake_secret_ctx()),
                                                 tuple(self.handshakes)))
        self.write_protected_handshake(finished)

    def _had_early_data(self) -> bool:
        for idx in range(0, len(self.handshakes)):
            hs = self.handshakes[idx]
            if hs.handshake_type == HandshakeType.encrypted_extensions:
                assert idx == 2, f"wrong order of encrypted_extensions:{idx}"
                encrypted_extensions: EncryptedExtensions = hs.handshake
                for ext in encrypted_extensions.extensions:
                    if ext.ext_type == ExtensionType.early_data:
                        return True
                return False
        assert False, f"no encrypted extensions found!"

    def write_application_data(self, app_data: bytes):
        assert self.state == TLSClientMachineState.CONNECTED or self._use_psk, \
            f"cannot send application data before connection established"
        records = self.construct_write_tls_cipher_text(ContentType.application_data, app_data)
        self.transport.write(b"".join((record.pack() for record in records)))
        self.logger.debug(f"write {len(app_data)} bytes application data")

    def write_application_data_async(self, app_data: bytes):
        self._user_write_data.appendleft(app_data)
        self._need_write_data_event.set()

    def read_application_data(self) -> bytes:
        if len(self._user_recv_data) > 0:
            return self._user_recv_data.pop()
        return b""

    def _handshake_ctx(self, handshake_type: HandshakeType, count: int = 1) -> typing.Tuple[Handshake, ...]:
        """all the handshake added as the order should be
        truncate the handshake context to use under any state
        :param handshake_type:
        :param count: used to distinguish the client/server handshake
        :return:
        """
        counter = 0
        for idx in range(0, len(self.handshakes)):
            if handshake_type == self.handshakes[idx].handshake_type:
                counter += 1
            if count <= counter:
                return tuple(self.handshakes[:idx + 1])
        return ()

    def _early_secret_ctx(self) -> typing.Tuple[Handshake, ...]:
        return self._handshake_ctx(HandshakeType.client_hello)

    def _handshake_secret_ctx(self) -> typing.Tuple[Handshake, ...]:
        return self._handshake_ctx(HandshakeType.server_hello)

    def _application_secret_ctx(self) -> typing.Tuple[Handshake, ...]:
        return self._handshake_ctx(HandshakeType.finished)

    def _resumption_ctx(self) -> typing.Tuple[Handshake, ...]:
        return self._handshake_ctx(HandshakeType.finished, 2)
