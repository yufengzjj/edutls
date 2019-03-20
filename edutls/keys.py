import typing

from edutls.types import Protocol, PackableInt, Vector, switch
from edutls.extension import CipherSuite
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM, ChaCha20Poly1305


class HkdfLabel(Protocol):
    def __init__(self, length: int, label: bytes, context: bytes):
        self.length = PackableInt(2, length)
        self.label = Vector(1, b"tls13 " + label)
        self.context = Vector(1, context)

    def pack(self) -> bytes:
        return self.length.pack() + self.label.pack() + self.context.pack()

    def unpack(self, data: bytes) -> bytes:
        pass


class HKDF:
    def __init__(self, algorithm: hashes.HashAlgorithm):
        self._algorithm = algorithm
        self._backend = default_backend()

    def extract(self, key_material: bytes, salt: bytes) -> bytes:
        if key_material is None or len(key_material) == 0:
            key_material = b"\x00" * self._algorithm.digest_size
        if salt is None or len(salt) == 0:
            salt = b"\x00" * self._algorithm.digest_size
        h = hmac.HMAC(salt, self._algorithm, backend=self._backend)
        h.update(key_material)
        return h.finalize()

    def expand(self, key_material: bytes, info: bytes, length: int) -> bytes:
        max_length = 255 * self._algorithm.digest_size
        if length > max_length:
            raise ValueError(f"Can not derive keys larger than {max_length} octets.")
        if info is None:
            info = b""
        output = [b""]
        counter: int = 1

        while self._algorithm.digest_size * (len(output) - 1) < length:
            h = hmac.HMAC(key_material, self._algorithm, backend=self._backend)
            h.update(output[-1])
            h.update(info)
            h.update(counter.to_bytes(1, "big"))
            output.append(h.finalize())
            counter += 1

        return b"".join(output)[:length]

    def expand_label(self, key_material: bytes, label: bytes, context: bytes, length: int) -> bytes:
        hkdf_label = HkdfLabel(length, label, context)
        return self.expand(key_material, hkdf_label.pack(), length)


class KeyDerivation:
    def __init__(self, cipher_suite: CipherSuite,
                 psk: bytes = None,
                 ecdhe: bytes = None):
        self._cipher_suite = cipher_suite
        self._algorithm: hashes.HashAlgorithm = self.hash_algorithm()
        self._backend = default_backend()
        self._psk = psk
        self._ecdhe = ecdhe
        self._hkdf = HKDF(self._algorithm)
        self._early_secret: bytes = None
        self._ext_binder_key: bytes = None
        self._res_binder_key: bytes = None
        self._client_early_traffic_secret: bytes = None
        self._early_exporter_master_secret: bytes = None
        self._handshake_secret: bytes = None
        self._client_handshake_traffic_secret: bytes = None
        self._server_handshake_traffic_secret: bytes = None
        self._master_secret: bytes = None
        self._client_application_traffic_secret_0: bytes = None
        self._client_application_traffic_secret_N: bytes = None
        self._server_application_traffic_secret_0: bytes = None
        self._server_application_traffic_secret_N: bytes = None
        self._exporter_master_secret: bytes = None
        self._resumption_master_secret: bytes = None
        self._handshake_read_seq: PackableInt = PackableInt(8, 0)
        self._application_read_seq: PackableInt = PackableInt(8, 0)
        self._early_write_seq: PackableInt = PackableInt(8, 0)
        self._handshake_write_seq: PackableInt = PackableInt(8, 0)
        self._application_write_seq: PackableInt = PackableInt(8, 0)
        self._client_early_traffic_write_key: bytes = None
        self._client_early_traffic_write_iv: bytes = None
        self._client_handshake_traffic_write_key: bytes = None
        self._client_handshake_traffic_write_iv: bytes = None
        self._server_handshake_traffic_write_key: bytes = None
        self._server_handshake_traffic_write_iv: bytes = None
        self._client_application_traffic_write_key: bytes = None
        self._client_application_traffic_write_iv: bytes = None
        self._server_application_traffic_write_key: bytes = None
        self._server_application_traffic_write_iv: bytes = None
        self._client_handshake_finished_key: bytes = None
        self._server_handshake_finished_key: bytes = None
        self._post_handshake_finished_key: bytes = None

    def hash_algorithm(self):
        if self._cipher_suite == CipherSuite.TLS_AES_256_GCM_SHA384:
            return hashes.SHA384()
        else:
            return hashes.SHA256()

    def cipher_suite(self):
        return self._cipher_suite

    def record_protection_algorithm(self):
        for case in switch(self._cipher_suite):
            if case(CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384):
                return AESGCM
            if case(CipherSuite.TLS_AES_128_CCM_8_SHA256, CipherSuite.TLS_AES_128_CCM_SHA256):
                return AESCCM
            if case(CipherSuite.TLS_CHACHA20_POLY1305_SHA256):
                return ChaCha20Poly1305

    def transcript_hash(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        """
        the transcript hash is always taken from the
        following sequence of handshake messages, starting at the first
        ClientHello and including only those messages that were sent:
        ClientHello, HelloRetryRequest, ClientHello, ServerHello,
        EncryptedExtensions, server CertificateRequest, server Certificate,
        server CertificateVerify, server Finished, EndOfEarlyData, client
        Certificate, client CertificateVerify, client Finished.
        :param messages:
        :return:
        """
        return self.just_hash(b"".join((handshake.pack() for handshake in messages)))

    def just_hash(self, data: bytes) -> bytes:
        digest = hashes.Hash(self._algorithm, backend=self._backend)
        digest.update(data)
        return digest.finalize()

    def traffic_key_iv_len(self) -> typing.Tuple[int, int]:
        if self._cipher_suite in (CipherSuite.TLS_AES_256_GCM_SHA384, CipherSuite.TLS_CHACHA20_POLY1305_SHA256):
            return 32, 12
        else:
            return 16, 12

    def derive_secret(self, secret: bytes, label: bytes, messages: typing.Tuple[Protocol] = ()) -> bytes:
        return self._hkdf.expand_label(secret, label, self.transcript_hash(messages), self._algorithm.digest_size)

    def traffic_key(self, secret: bytes) -> bytes:
        return self._hkdf.expand_label(secret, b"key", b"", self.traffic_key_iv_len()[0])

    def traffic_iv(self, secret) -> bytes:
        return self._hkdf.expand_label(secret, b"iv", b"", self.traffic_key_iv_len()[1])

    def client_early_traffic_write_key(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        if self._client_early_traffic_write_key is None:
            self._client_early_traffic_write_key = self.traffic_key(self.client_early_traffic_secret(messages))
        return self._client_early_traffic_write_key

    def client_early_traffic_write_iv(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        if self._client_early_traffic_write_iv is None:
            self._client_early_traffic_write_iv = self.traffic_iv(self.client_early_traffic_secret(messages))
        return self._client_early_traffic_write_iv

    def client_handshake_traffic_write_key(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        if self._client_handshake_traffic_write_key is None:
            self._client_handshake_traffic_write_key = self.traffic_key(self.client_handshake_traffic_secret(messages))
        return self._client_handshake_traffic_write_key

    def client_handshake_traffic_write_iv(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        if self._client_handshake_traffic_write_iv is None:
            self._client_handshake_traffic_write_iv = self.traffic_iv(self.client_handshake_traffic_secret(messages))
        return self._client_handshake_traffic_write_iv

    def server_handshake_traffic_write_key(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        if self._server_handshake_traffic_write_key is None:
            self._server_handshake_traffic_write_key = self.traffic_key(self.server_handshake_traffic_secret(messages))
        return self._server_handshake_traffic_write_key

    def server_handshake_traffic_write_iv(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        if self._server_handshake_traffic_write_iv is None:
            self._server_handshake_traffic_write_iv = self.traffic_iv(self.server_handshake_traffic_secret(messages))
        return self._server_handshake_traffic_write_iv

    def client_application_traffic_write_key(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        if self._client_application_traffic_write_key is None:
            self._client_application_traffic_write_key = self.traffic_key(
                self.client_application_traffic_secret_0(messages))
        return self._client_application_traffic_write_key

    def client_application_traffic_write_iv(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        if self._client_application_traffic_write_iv is None:
            self._client_application_traffic_write_iv = self.traffic_iv(
                self.client_application_traffic_secret_0(messages))
        return self._client_application_traffic_write_iv

    def server_application_traffic_write_key(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        if self._server_application_traffic_write_key is None:
            self._server_application_traffic_write_key = self.traffic_key(
                self.server_application_traffic_secret_0(messages))
        return self._server_application_traffic_write_key

    def server_application_traffic_write_iv(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        if self._server_application_traffic_write_iv is None:
            self._server_application_traffic_write_iv = self.traffic_iv(
                self.server_application_traffic_secret_0(messages))
        return self._server_application_traffic_write_iv

    def client_early_traffic_write_nonce(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        nonce = self._early_write_seq.value ^ int.from_bytes(self.client_early_traffic_write_iv(messages), "big")
        self._early_write_seq.value += 1
        return nonce.to_bytes(self.traffic_key_iv_len()[1], "big")

    def client_handshake_traffic_write_nonce(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        nonce = self._handshake_write_seq.value ^ int.from_bytes(self.client_handshake_traffic_write_iv(messages),
                                                                 "big")
        self._handshake_write_seq.value += 1
        return nonce.to_bytes(self.traffic_key_iv_len()[1], "big")

    def server_handshake_traffic_write_nonce(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        nonce = self._handshake_read_seq.value ^ int.from_bytes(self.server_handshake_traffic_write_iv(messages), "big")
        self._handshake_read_seq.value += 1
        return nonce.to_bytes(self.traffic_key_iv_len()[1], "big")

    def client_application_traffic_write_nonce(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        nonce = self._application_write_seq.value ^ int.from_bytes(self.client_application_traffic_write_iv(messages),
                                                                   "big")
        self._application_write_seq.value += 1
        return nonce.to_bytes(self.traffic_key_iv_len()[1], "big")

    def server_application_traffic_write_nonce(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        nonce = self._application_read_seq.value ^ int.from_bytes(self.server_application_traffic_write_iv(messages),
                                                                  "big")
        self._application_read_seq.value += 1
        return nonce.to_bytes(self.traffic_key_iv_len()[1], "big")

    def finished_key(self, base_key) -> bytes:
        return self._hkdf.expand_label(base_key, b"finished", b"", self._algorithm.digest_size)

    def early_secret(self) -> bytes:
        if self._early_secret is None:
            self._early_secret = self._hkdf.extract(self._psk, b"")
        return self._early_secret

    def ext_binder_key(self) -> bytes:
        if self._ext_binder_key is None:
            self._ext_binder_key = self.derive_secret(self.early_secret(), b"ext binder")
        return self._ext_binder_key

    def res_binder_key(self) -> bytes:
        if self._res_binder_key is None:
            self._res_binder_key = self.derive_secret(self.early_secret(), b"res binder")
        return self._res_binder_key

    def client_early_traffic_secret(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        if self._client_early_traffic_secret is None:
            self._client_early_traffic_secret = self.derive_secret(self.early_secret(), b"c e traffic", messages)
        return self._client_early_traffic_secret

    def early_exporter_master_secret(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        if self._early_exporter_master_secret is None:
            self._early_exporter_master_secret = self.derive_secret(self.early_secret(), b"e exp master", messages)
        return self._early_exporter_master_secret

    def handshake_secret(self) -> bytes:
        if self._handshake_secret is None:
            salt: bytes = self.derive_secret(self.early_secret(), b"derived")
            self._handshake_secret = self._hkdf.extract(self._ecdhe, salt)
        return self._handshake_secret

    def client_handshake_traffic_secret(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        if self._client_handshake_traffic_secret is None:
            self._client_handshake_traffic_secret = self.derive_secret(self.handshake_secret(), b"c hs traffic",
                                                                       messages)
        return self._client_handshake_traffic_secret

    def server_handshake_traffic_secret(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        if self._server_handshake_traffic_secret is None:
            self._server_handshake_traffic_secret = self.derive_secret(self.handshake_secret(), b"s hs traffic",
                                                                       messages)
        return self._server_handshake_traffic_secret

    def master_secret(self) -> bytes:
        if self._master_secret is None:
            salt: bytes = self.derive_secret(self.handshake_secret(), b"derived")
            self._master_secret = self._hkdf.extract(b"", salt)
        return self._master_secret

    def client_application_traffic_secret_0(self, messages: typing.Tuple[Protocol]) -> bytes:
        if self._client_application_traffic_secret_0 is None:
            self._client_application_traffic_secret_0 = self.derive_secret(self.master_secret(), b"c ap traffic",
                                                                           messages)
        return self._client_application_traffic_secret_0

    def client_application_traffic_secret_N(self) -> bytes:
        assert self._client_application_traffic_secret_0 is not None, \
            "_client_application_traffic_secret_N need client_application_traffic_secret_0"
        if self._client_application_traffic_secret_N is None:
            self._client_application_traffic_secret_N = self._client_application_traffic_secret_0
        self._client_application_traffic_secret_N = self._hkdf.expand_label(self._client_application_traffic_secret_N,
                                                                            b"traffic upd",
                                                                            b"", self._algorithm.digest_size)
        self._client_application_traffic_secret_0 = self._client_application_traffic_secret_N
        return self._client_application_traffic_secret_N

    def server_application_traffic_secret_0(self, messages: typing.Tuple[Protocol]) -> bytes:
        if self._server_application_traffic_secret_0 is None:
            self._server_application_traffic_secret_0 = self.derive_secret(self.master_secret(), b"s ap traffic",
                                                                           messages)
        return self._server_application_traffic_secret_0

    def server_application_traffic_secret_N(self) -> bytes:
        assert self._server_application_traffic_secret_0 is not None, \
            "server_application_traffic_secret_N need server_application_traffic_secret_0"
        if self._server_application_traffic_secret_N is None:
            self._server_application_traffic_secret_N = self._server_application_traffic_secret_0
        self._server_application_traffic_secret_N = self._hkdf.expand_label(self._server_application_traffic_secret_N,
                                                                            b"traffic upd", b"",
                                                                            self._algorithm.digest_size)
        self._server_application_traffic_secret_0 = self._server_application_traffic_secret_N
        return self._server_application_traffic_secret_N

    def exporter_master_secret(self, messages: typing.Tuple[Protocol]) -> bytes:
        if self._exporter_master_secret is None:
            self._exporter_master_secret = self.derive_secret(self.master_secret(), b"exp master",
                                                              messages)
        return self._exporter_master_secret

    def resumption_master_secret(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        if self._resumption_master_secret is None:
            self._resumption_master_secret = self.derive_secret(self.master_secret(), b"res master",
                                                                messages)
        return self._resumption_master_secret

    def resume_psk(self, ticket_nonce: bytes, messages: typing.Tuple[Protocol, ...]) -> bytes:
        return self._hkdf.expand_label(self.resumption_master_secret(messages), b"resumption", ticket_nonce,
                                       self._algorithm.digest_size)

    def client_handshake_finished_key(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        if self._client_handshake_finished_key is None:
            self._client_handshake_finished_key = self._hkdf.expand_label(
                self.client_handshake_traffic_secret(messages), b"finished", b"", self._algorithm.digest_size)
        return self._client_handshake_finished_key

    def server_handshake_finished_key(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        if self._server_handshake_finished_key is None:
            self._server_handshake_finished_key = self._hkdf.expand_label(
                self.server_handshake_traffic_secret(messages), b"finished", b"", self._algorithm.digest_size)
        return self._server_handshake_finished_key

    def post_handshake_finished_key(self, messages: typing.Tuple[Protocol, ...]) -> bytes:
        if self._post_handshake_finished_key is None:
            self._post_handshake_finished_key = self._hkdf.expand_label(
                self.client_application_traffic_secret_0(messages), b"finished", b"", self._algorithm.digest_size)
        return self._post_handshake_finished_key

    def hmac_verify(self, finished_key: bytes, messages: typing.Tuple[Protocol, ...]) -> bytes:
        from cryptography.hazmat.primitives.hmac import HMAC
        h = HMAC(finished_key, self._algorithm, self._backend)
        h.update(self.transcript_hash(messages))
        return h.finalize()

    def just_hmac_verify(self, finished_key: bytes, data: bytes):
        from cryptography.hazmat.primitives.hmac import HMAC
        h = HMAC(finished_key, self._algorithm, self._backend)
        h.update(self.just_hash(data))
        return h.finalize()

    def use_psk(self) -> bool:
        return self._psk is not None

    def hash_digest_size(self) -> int:
        return self._algorithm.digest_size
