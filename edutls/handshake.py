import os
import typing
from io import BytesIO

from edutls.extension import Extension, CipherSuite, CompressionMethod, SignatureScheme, EarlyDataIndication, ExtensionType, \
    SupportedVersions, KeyShareServerHello
from edutls.record import ContentType
from edutls.types import UInt8Enum, Protocol, ProtocolVersion, Vector, PackableInt, switch


class HandshakeType(UInt8Enum):
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    message_hash = 254


class IHandshake(Protocol):
    def pack(self) -> bytes:
        return b""

    def unpack(self, data: bytes) -> bytes:
        return data


class Handshake(Protocol):
    def __init__(self, message: IHandshake = None):
        if message is None:
            message = IHandshake()
        assert issubclass(type(message), IHandshake)
        self.handshake = message
        self.handshake_data = message.pack()
        self.handshake_type: HandshakeType = message.type

    def pack(self) -> bytes:
        return self.handshake_type.pack() + Vector(3, self.handshake_data).pack()

    def unpack(self, data: bytes) -> bytes:
        self.handshake_type, data = HandshakeType.unpack(data)
        size = PackableInt(3, 0)
        data = size.unpack(data)
        assert len(data) >= size.value, f"incomplete handshake"
        self.handshake_data = data[:size.value]
        return data[size.value:]

    @property
    def type(self) -> ContentType:
        return ContentType.handshake


class ClientHello(IHandshake):
    def __init__(self, extensions: typing.Tuple[Extension, ...] = (),
                 cipher_suites: typing.Tuple[CipherSuite] = (
                         CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384,
                         CipherSuite.TLS_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_AES_128_CCM_SHA256,
                         CipherSuite.TLS_AES_128_CCM_8_SHA256),
                 legacy_version: int = 0x0303, legacy_session_id: bytes = b"",
                 legacy_compression_methods: typing.Tuple[CompressionMethod] = (CompressionMethod.null,)):
        self.legacy_record_version: int = legacy_version
        self.random: bytes = os.urandom(32)
        self.legacy_session_id: bytes = legacy_session_id
        self.cipher_suites: typing.Tuple[CipherSuite] = cipher_suites
        self.legacy_compression_methods: typing.Tuple[CompressionMethod] = legacy_compression_methods
        self.extensions: typing.Tuple[Extension, ...] = extensions

    def pack(self) -> bytes:
        data = BytesIO()
        data.write(ProtocolVersion(self.legacy_record_version).pack())
        data.write(self.random)
        data.write(Vector(1, self.legacy_session_id).pack())
        cipher_suites_data = b"".join((cipher_suite.pack() for cipher_suite in self.cipher_suites))
        data.write(Vector(2, cipher_suites_data).pack())
        legacy_compression_methods_data = b"".join((
            legacy_compression_method.pack() for legacy_compression_method in self.legacy_compression_methods))
        data.write(Vector(1, legacy_compression_methods_data).pack())
        extensions_data = b"".join((extension.pack() for extension in self.extensions))
        data.write(Vector(2, extensions_data).pack())
        return data.getvalue()

    def unpack(self, data: bytes) -> bytes:
        pass

    @property
    def type(self):
        return HandshakeType.client_hello


class ServerHello(IHandshake):
    def __init__(self, extensions: typing.Tuple[Extension, ...] = (),
                 cipher_suite: CipherSuite = CipherSuite.TLS_AES_128_GCM_SHA256,
                 legacy_version: int = 0x0303,
                 legacy_session_id_echo: bytes = b"",
                 legacy_compression_method: CompressionMethod = CompressionMethod.null):
        self.legacy_version = legacy_version
        self.random: bytes = os.urandom(32)
        self.legacy_session_id_echo = legacy_session_id_echo
        self.cipher_suite: CipherSuite = cipher_suite
        self.legacy_compression_method: CompressionMethod = legacy_compression_method
        self.extensions: typing.Tuple[Extension, ...] = extensions

    def pack(self) -> bytes:
        pass

    def unpack(self, data: bytes) -> bytes:
        legacy_version_int = ProtocolVersion(0)
        data = legacy_version_int.unpack(data)
        self.legacy_version = legacy_version_int.value

        assert len(data) >= 32, f"no enough bytes to unpack random"
        self.random = data[:32]
        data = data[32:]

        legacy_session_id_echo_vec = Vector(1)
        data = legacy_session_id_echo_vec.unpack(data)
        self.legacy_session_id_echo = legacy_session_id_echo_vec.data

        self.cipher_suite, data = CipherSuite.unpack(data)
        self.legacy_compression_method, data = CompressionMethod.unpack(data)
        extension_vec = Vector(2)
        data = extension_vec.unpack(data)
        ext_data: bytes = extension_vec.data
        extensions = []
        while len(ext_data) > 0:
            ext = Extension()
            ext_data = ext.unpack(ext_data)
            extension = Extension.construct(ext.ext_type)
            if extension:
                ext.ext: Vector
                extension.unpack(ext.ext.data)
                ext.ext = extension
            extensions.append(ext)
        self.extensions = tuple(extensions)
        return data

    def is_retry(self):
        return self.random == b"cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"

    @property
    def type(self):
        return HandshakeType.server_hello

    @property
    def selected_version(self):
        for ext in self.extensions:
            if ext.ext_type == ExtensionType.supported_versions:
                ext.ext: SupportedVersions
                return ext.ext.selected_version
        return 0xffff

    @property
    def selected_cipher_suite(self) -> str:
        return self.cipher_suite.name

    @property
    def selected_supported_group(self) -> str:
        for ext in self.extensions:
            if ext.ext_type == ExtensionType.key_share:
                ext.ext: KeyShareServerHello
                return ext.ext.key_share.key_exchange.group.name
        return "none"


class EncryptedExtensions(IHandshake):
    def __init__(self, extensions: typing.Tuple[Extension, ...] = ()):
        self.extensions = extensions

    def pack(self) -> bytes:
        extensions_data: bytes = b"".join(extension.pack() for extension in self.extensions)
        return Vector(2, extensions_data).pack()

    def unpack(self, data: bytes) -> bytes:
        extension_vec = Vector(2)
        data = extension_vec.unpack(data)
        ext_data: bytes = extension_vec.data
        extensions = []
        while len(ext_data) > 0:
            ext = Extension()
            ext_data = ext.unpack(ext_data)
            extension = Extension.construct(ext.ext_type)
            if extension:
                ext.ext: Vector
                extension.unpack(ext.ext.data)
                ext.ext = extension
            extensions.append(ext)
        extensions = []
        self.extensions = tuple(extensions)
        return data

    @property
    def type(self):
        return HandshakeType.encrypted_extensions


class EndOfEarlyData(IHandshake):

    def pack(self) -> bytes:
        return b""

    def unpack(self, data: bytes) -> bytes:
        return data

    @property
    def type(self):
        return HandshakeType.end_of_early_data


class CertificateRequest(IHandshake):
    def __init__(self, certificate_request_context: bytes = b"", extensions: typing.Tuple[Extension, ...] = ()):
        self.certificate_request_context = certificate_request_context
        # signature_algorithms, signature_algorithms_cert, certificate_authorities
        # oid_filters
        # may appear here
        self.extensions = extensions

    def pack(self) -> bytes:
        extensions_data: bytes = b"".join(extension.pack() for extension in self.extensions)
        return Vector(1, self.certificate_request_context).pack() + Vector(2, extensions_data).pack()

    def unpack(self, data: bytes) -> bytes:
        cert_req_ctx_vvc = Vector(1)
        data = cert_req_ctx_vvc.unpack(data)
        self.certificate_request_context = cert_req_ctx_vvc.data
        extension_vec = Vector(2)
        data = extension_vec.unpack(data)
        ext_data: bytes = extension_vec.data
        extensions = []
        while len(ext_data) > 0:
            ext = Extension()
            ext_data = ext.unpack(ext_data)
            extensions.append(ext)
        self.extensions = tuple(extensions)
        return data

    @property
    def type(self):
        return HandshakeType.certificate_request


class CertificateType(UInt8Enum):
    X509 = 0,
    RawPublicKey = 2


class CertificateEntry(Protocol):
    def __init__(self, cert_data: bytes = b"", extensions: typing.Tuple[Extension, ...] = ()):
        self.cert_data = cert_data
        self.extensions = extensions

    def pack(self) -> bytes:
        return Vector(3, self.cert_data).pack() + Vector(2, self.extensions).pack()

    def unpack(self, data: bytes) -> bytes:
        cert_data_vec = Vector(3)
        data = cert_data_vec.unpack(data)
        self.cert_data = cert_data_vec.data
        ext_data_vec = Vector(2)
        data = ext_data_vec.unpack(data)
        ext_data: bytes = ext_data_vec.data
        extensions = []
        while len(ext_data) > 0:
            ext = Extension()
            ext_data = ext.unpack(ext_data)
            extensions.append(ext)
        self.extensions = tuple(extensions)
        return data


class Certificate(IHandshake):
    def __init__(self, cert_req_ctx: bytes = b"", cert_entries: typing.Tuple[CertificateEntry, ...] = ()):
        self.cert_req_ctx = cert_req_ctx
        self.cert_entries = cert_entries

    def pack(self) -> bytes:
        return Vector(1, self.cert_req_ctx).pack() + Vector(3, self.cert_entries).pack()

    def unpack(self, data: bytes) -> bytes:
        cert_req_ctx_vec = Vector(1)
        data = cert_req_ctx_vec.unpack(data)
        self.cert_req_ctx = cert_req_ctx_vec.data
        cert_entries_vec = Vector(3)
        data = cert_entries_vec.unpack(data)
        cert_entries_data: bytes = cert_entries_vec.data
        cert_entries = []
        while len(cert_entries_data) > 0:
            cert_entry = CertificateEntry()
            cert_entries_data = cert_entry.unpack(cert_entries_data)
            cert_entries.append(cert_entry)
        self.cert_entries = tuple(cert_entries)
        return data

    @property
    def type(self):
        return HandshakeType.certificate


class CertificateVerify(IHandshake):
    def __init__(self, algorithm: SignatureScheme = SignatureScheme.ecdsa_secp256r1_sha256, signature: bytes = b""):
        self.algorithm = algorithm
        self.signature = signature

    def pack(self) -> bytes:
        return self.algorithm.pack() + Vector(2, self.signature).pack()

    def unpack(self, data: bytes) -> bytes:
        self.algorithm, data = SignatureScheme.unpack(data)
        signature_vec = Vector(2)
        data = signature_vec.unpack(data)
        self.signature = signature_vec.data
        return data

    @property
    def type(self):
        return HandshakeType.certificate_verify


class Finished(IHandshake):
    def __init__(self, verify_data: bytes = b""):
        self.verify_data = verify_data

    def pack(self) -> bytes:
        return self.verify_data

    def unpack(self, data: bytes) -> bytes:
        """
        it's your duty to ensure that all the data are Finished data
        :param data:
        """
        self.verify_data = data
        return b""

    @property
    def type(self):
        return HandshakeType.finished


class NewSessionTicket(IHandshake):
    def __init__(self, ticket: bytes = b"", ticket_nonce: bytes = b"",
                 extensions: typing.Tuple[Extension, ...] = (),
                 ticket_lifetime: int = 604800,
                 ticket_age_add: int = None):
        if ticket_age_add is None:
            ticket_age_add = int.from_bytes(os.urandom(4), "big")
        self.ticket = ticket
        self.ticket_nonce = ticket_nonce
        self.extensions = extensions
        self.ticket_lifetime = ticket_lifetime
        self.ticket_age_add = ticket_age_add
        self.psk: bytes = None

    def pack(self) -> bytes:
        return PackableInt(4, self.ticket_lifetime).pack() + PackableInt(4, self.ticket_age_add).pack() \
               + Vector(1, self.ticket_nonce).pack() + Vector(2, self.ticket).pack() + Vector(2, self.extensions).pack()

    def unpack(self, data: bytes) -> bytes:
        ticket_lifetime_int = PackableInt(4, 0)
        data = ticket_lifetime_int.unpack(data)
        self.ticket_lifetime = ticket_lifetime_int.value

        ticket_age_add_int = PackableInt(4, 0)
        data = ticket_age_add_int.unpack(data)
        self.ticket_age_add = ticket_age_add_int.value

        ticket_nonce_vec = Vector(1)
        data = ticket_nonce_vec.unpack(data)
        self.ticket_nonce = ticket_nonce_vec.data

        ticket_vec = Vector(2)
        data = ticket_vec.unpack(data)
        self.ticket = ticket_vec.data

        ext_vec = Vector(2)
        data = ext_vec.unpack(data)
        ext_data: bytes = ext_vec.data

        extensions = []
        while len(ext_data) > 0:
            ext = Extension()
            ext_data = ext.unpack(ext_data)
            extension = Extension.construct(ext.ext_type)
            if extension:
                ext.ext: Vector
                extension.unpack(ext.ext.data)
                ext.ext = extension
            extensions.append(ext)
        self.extensions = tuple(extensions)
        return data

    @property
    def max_early_data_size(self):
        if len(self.extensions) <= 0:
            return -1
        else:
            early_data: EarlyDataIndication = self.extensions[0]
            return early_data.max_early_data_size()

    @property
    def type(self):
        return HandshakeType.new_session_ticket


class KeyUpdateRequest(UInt8Enum):
    update_not_requested = 0,
    update_requested = 1,


class KeyUpdate(IHandshake):
    def __init__(self, update: KeyUpdateRequest = KeyUpdateRequest.update_not_requested):
        self.update: KeyUpdateRequest = update

    def pack(self) -> bytes:
        return self.update.pack()

    def unpack(self, data: bytes) -> bytes:
        self.update: KeyUpdateRequest
        self.update, data = self.update.unpack(data)
        return data
