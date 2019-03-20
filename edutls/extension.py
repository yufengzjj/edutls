import typing

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from edutls.types import UInt16Enum, Protocol, ProtocolVersion, Vector, UInt8Enum, PackableInt, switch


class ExtensionType(UInt16Enum):
    server_name = 0,  # RFC 6066
    max_fragment_length = 1,  # RFC 6066
    status_request = 5,  # RFC 6066
    supported_groups = 10,  # RFC 8422, 7919
    signature_algorithms = 13,  # RFC 8446
    use_srtp = 14,  # RFC 5764
    heartbeat = 15,  # RFC 6520
    application_layer_protocol_negotiation = 16,  # RFC 7301
    signed_certificate_timestamp = 18,  # RFC 6962
    client_certificate_type = 19,  # RFC 7250
    server_certificate_type = 20,  # RFC 7250
    padding = 21,  # RFC 7685
    pre_shared_key = 41,  # RFC 8446
    early_data = 42,  # RFC 8446
    supported_versions = 43,  # RFC 8446
    cookie = 44,  # RFC 8446
    psk_key_exchange_modes = 45,  # RFC 8446
    certificate_authorities = 47,  # RFC 8446
    oid_filters = 48,  # RFC 8446
    post_handshake_auth = 49,  # RFC 8446
    signature_algorithms_cert = 50,  # RFC 8446
    key_share = 51,  # RFC 8446


class SupportedVersions(Protocol):
    def __init__(self, versions: typing.Tuple[ProtocolVersion, ...] = None):
        if versions is None:
            versions = (ProtocolVersion(0x0304),)
        self.versions = versions

    def pack(self) -> bytes:
        version_data = b"".join((version.pack() for version in self.versions))
        return Vector(1, version_data).pack()

    def unpack(self, data: bytes) -> bytes:
        return self.versions[0].unpack(data)

    @property
    def type(self):
        return ExtensionType.supported_versions

    @property
    def selected_version(self) -> int:
        return self.versions[0].value


class NamedGroup(UInt16Enum):
    #  Elliptic Curve Groups (ECDHE)
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    x25519 = 0x001D,
    x448 = 0x001E,
    #  Finite Field Groups (DHE)
    ffdhe2048 = 0x0100,
    ffdhe3072 = 0x0101,
    ffdhe4096 = 0x0102,
    ffdhe6144 = 0x0103,
    ffdhe8192 = 0x0104,


class NamedGroupList(Protocol):

    def __init__(self, supported_groups: typing.Tuple[NamedGroup] = (
            NamedGroup.x25519, NamedGroup.secp256r1, NamedGroup.secp384r1, NamedGroup.secp521r1, NamedGroup.x448,
            NamedGroup.ffdhe2048, NamedGroup.ffdhe3072, NamedGroup.ffdhe4096, NamedGroup.ffdhe6144,
            NamedGroup.ffdhe8192,)):
        self.groups = supported_groups

    def pack(self) -> bytes:
        groups_data = b"".join((group.pack() for group in self.groups))
        return Vector(2, groups_data).pack()

    def unpack(self, data: bytes) -> bytes:
        pass

    @property
    def type(self):
        return ExtensionType.supported_groups


class CompressionMethod(UInt8Enum):
    null = 0,
    DEFLATE = 1


class CipherSuite(UInt16Enum):
    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    TLS_AES_128_CCM_SHA256 = 0x1304
    TLS_AES_128_CCM_8_SHA256 = 0x1305


class KeyExchange(Protocol):
    def __init__(self, group=NamedGroup.x25519):
        self.group: NamedGroup = group
        self.private: typing.Union[X25519PrivateKey, ec.EllipticCurvePrivateKey, dh.DHPrivateKey] = None
        self.public: bytes = None

    def pack(self) -> bytes:
        func_name = "pack_" + self.group.name
        pack_func: typing.Callable[[], bytes] = getattr(self, func_name)
        assert pack_func is not None, f"no KeyExchange pack function:{func_name}"
        return pack_func()

    def pack_x25519(self) -> bytes:
        private_key: X25519PrivateKey = X25519PrivateKey.generate()
        public_key: X25519PublicKey = private_key.public_key()
        self.private = private_key
        self.public = public_key.public_bytes(encoding=serialization.Encoding.Raw,
                                              format=serialization.PublicFormat.Raw)
        return self.public

    def pack_secp256r1(self) -> bytes:
        private_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key: ec.EllipticCurvePublicKey = private_key.public_key()
        self.private = private_key
        self.public = public_key.public_bytes(encoding=serialization.Encoding.X962,
                                              format=serialization.PublicFormat.UncompressedPoint)
        return self.public

    def pack_ffdhe2048(self) -> bytes:
        parameters: dh.DHParameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        private_key: dh.DHPrivateKey = parameters.generate_private_key()
        public_key: dh.DHPublicKey = private_key.public_key()
        public_numbers: dh.DHPublicNumbers = public_key.public_numbers()
        public_numbers.y: int
        self.private = private_key
        self.public = public_numbers.y.to_bytes(int(public_key.key_size / 8), "big")
        return self.public

    def unpack(self, data: bytes) -> bytes:
        func_name = "unpack_" + self.group.name
        unpack_func: typing.Callable[[bytes], bytes] = getattr(self, func_name)
        assert unpack_func is not None, f"no KeyExchange unpack function:{func_name}"
        return unpack_func(data)

    def unpack_x25519(self, data: bytes) -> bytes:
        assert len(data) >= 32, f"not enough bytes to unpack x25519 public key"
        self.public = data[:32]
        return data[32:]

    def unpack_secp256r1(self, data: bytes) -> bytes:
        assert len(data) >= 65, f"not enough bytes to unpack secp256r1 public key"
        self.public = data[:65]
        return data[65:]

    def unpack_ffdhe2048(self, data: bytes) -> bytes:
        assert len(data) >= 256, f"not enough bytes to unpack ffdhe2048 public key"
        self.public = data[:256]
        return data[256:]

    def exchange(self, public: bytes) -> bytes:
        func_name = "exchange_" + self.group.name
        exchange_func: typing.Callable[[bytes], bytes] = getattr(self, func_name)
        assert exchange_func is not None, f"no KeyExchange exchange function:{func_name}"
        return exchange_func(public)

    def exchange_x25519(self, public: bytes) -> bytes:
        assert len(public) == 32, f"x25519 public key must be 32 bytes"
        public_key = X25519PublicKey.from_public_bytes(public)
        return self.private.exchange(public_key)

    def exchange_secp256r1(self, public: bytes) -> bytes:
        assert len(public) == 65, f"secp256r1 public key must be 65 bytes"
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public)
        return self.private.exchange(ec.ECDH(), public_key)

    def exchange_ffdhe2048(self, public: bytes) -> bytes:
        assert len(public) == 256, f"ffdhe2048 public key must be 256 bytes"
        self.private: dh.DHPrivateKey
        public_numbers = dh.DHPublicNumbers(int.from_bytes(public, "big"),
                                            self.private.parameters().parameter_numbers())
        public_key = public_numbers.public_key(default_backend())
        return self.private.exchange(public_key)


class KeyShareEntry(Protocol):
    def __init__(self, key_exchange: KeyExchange = None):
        if key_exchange is None:
            key_exchange = KeyExchange(NamedGroup.x25519)
        self.key_exchange: KeyExchange = key_exchange

    def pack(self) -> bytes:
        key_exchange_data: bytes = self.key_exchange.pack()
        return self.key_exchange.group.pack() + Vector(2, key_exchange_data).pack()

    def unpack(self, data: bytes) -> bytes:
        self.key_exchange.group, data = NamedGroup.unpack(data)
        key_exchange_vec = Vector(2)
        data = key_exchange_vec.unpack(data)
        self.key_exchange.unpack(key_exchange_vec.data)
        return data

    @property
    def type(self):
        return ExtensionType.key_share


class KeyShareClientHello(Protocol):
    def __init__(self, key_shares: typing.Tuple[KeyShareEntry, ...] = ()):
        self.key_shares = key_shares

    def pack(self) -> bytes:
        key_shares_data = b"".join((key_share.pack() for key_share in self.key_shares))
        return Vector(2, key_shares_data).pack()

    def unpack(self, data: bytes) -> bytes:
        pass

    @property
    def type(self):
        return ExtensionType.key_share


class KeyShareServerHello(Protocol):

    def __init__(self, key_share: KeyShareEntry = None):
        if key_share is None:
            key_share = KeyShareEntry()
        self.key_share = key_share

    def pack(self) -> bytes:
        pass

    def unpack(self, data: bytes) -> bytes:
        return self.key_share.unpack(data)

    @property
    def type(self):
        return ExtensionType.key_share


class PskKeyExchangeMode(UInt8Enum):
    psk_ke = 0,
    psk_dhe_ke = 1


class PskKeyExchangeModes(Protocol):
    def __init__(self, psk_key_exchange_modes: typing.Tuple[PskKeyExchangeMode, ...] = None):
        if psk_key_exchange_modes is None:
            psk_key_exchange_modes = (PskKeyExchangeMode.psk_ke,)
        self.psk_key_exchange_modes = psk_key_exchange_modes

    def pack(self) -> bytes:
        return Vector(1, self.psk_key_exchange_modes).pack()

    def unpack(self, data: bytes) -> bytes:
        pass

    @property
    def type(self):
        return ExtensionType.psk_key_exchange_modes


class SignatureScheme(UInt16Enum):
    #  RSASSA-PKCS1-v1_5 algorithms
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,
    #  ECDSA algorithms
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,
    #  RSASSA-PSS algorithms with public key OID rsaEncryption
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,
    #  EdDSA algorithms
    ed25519 = 0x0807,
    ed448 = 0x0808,
    #  RSASSA-PSS algorithms with public key OID RSASSA-PSS
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,
    #  Legacy algorithms
    rsa_pkcs1_sha1 = 0x0201,
    ecdsa_sha1 = 0x0203,


class SignatureSchemeList(Protocol):
    def __init__(self, sig_schemes: typing.Tuple[SignatureScheme] = (
            SignatureScheme.rsa_pkcs1_sha256, SignatureScheme.rsa_pkcs1_sha384, SignatureScheme.rsa_pkcs1_sha512,
            SignatureScheme.ecdsa_secp256r1_sha256, SignatureScheme.ecdsa_secp384r1_sha384,
            SignatureScheme.ecdsa_secp521r1_sha512,
            SignatureScheme.rsa_pss_rsae_sha256, SignatureScheme.rsa_pss_rsae_sha384,
            SignatureScheme.rsa_pss_rsae_sha512, SignatureScheme.ed25519, SignatureScheme.ed448,
            SignatureScheme.rsa_pss_pss_sha256, SignatureScheme.rsa_pss_pss_sha384, SignatureScheme.rsa_pss_pss_sha512,
            SignatureScheme.rsa_pkcs1_sha1,
            SignatureScheme.ecdsa_sha1,
    )):
        self.sig_schemes = sig_schemes

    def pack(self) -> bytes:
        sig_schemes_data = b"".join((sig_scheme.pack() for sig_scheme in self.sig_schemes))
        return Vector(2, sig_schemes_data).pack()

    def unpack(self, data: bytes) -> bytes:
        pass

    @property
    def type(self):
        return ExtensionType.signature_algorithms


class PskIdentity(Protocol):
    def __init__(self, identity: bytes = b"", obfuscated_ticket_age: int = 0):
        self.obfuscated_ticket_age = obfuscated_ticket_age
        self.identity = identity

    def pack(self) -> bytes:
        return Vector(2, self.identity).pack() + PackableInt(4, self.obfuscated_ticket_age).pack()

    def unpack(self, data: bytes) -> bytes:
        pass


class PskBinderEntry(Protocol):
    def __init__(self, binder: bytes):
        self.binder = binder

    def pack(self) -> bytes:
        return Vector(1, self.binder).pack()

    def unpack(self, data: bytes) -> bytes:
        pass


class OfferedPsks(Protocol):
    def __init__(self, identities: typing.Tuple[PskIdentity, ...] = (),
                 binders: typing.Tuple[PskBinderEntry, ...] = ()):
        self.identities = identities
        self.binders = binders

    def pack(self) -> bytes:
        identities_data = b"".join((identity.pack() for identity in self.identities))
        binders_data = b"".join((binder.pack() for binder in self.binders))
        return Vector(2, identities_data).pack() + Vector(2, binders_data).pack()

    def unpack(self, data: bytes) -> bytes:
        pass


class SelectedIdentity(Protocol):
    def __init__(self, index: int = -1):
        self.index = index

    def pack(self) -> bytes:
        return PackableInt(2, self.index).pack()

    def unpack(self, data: bytes) -> bytes:
        assert len(data) >= 2, f"not enough bytes to unpack SelectedIdentity"
        self.index = int.from_bytes(data[:2], "big")
        return data[2:]


class PreSharedKeyExtension(Protocol):
    def __init__(self, ext: Protocol):
        self.ext = ext

    def pack(self) -> bytes:
        return self.ext.pack()

    def unpack(self, data: bytes) -> bytes:
        return self.ext.unpack(data)

    @property
    def type(self):
        return ExtensionType.pre_shared_key


class EarlyDataIndication(Protocol):

    def __init__(self, max_early_data_size: bytes = b""):
        self.early_data_size = max_early_data_size

    def pack(self) -> bytes:
        return self.early_data_size

    def unpack(self, data: bytes) -> bytes:
        """
        it's your duty to make sure that all the data is extension data
        :param data:
        :return:
        """
        self.early_data_size = data
        return b""

    def max_early_data_size(self):
        size = PackableInt(4, 0)
        if len(self.early_data_size) == 4:
            size.unpack(self.early_data_size)
        return size.value

    @property
    def type(self):
        return ExtensionType.early_data


class NameType(UInt8Enum):
    host_name = 0,


class ServerName(Protocol):
    def __init__(self, name: bytes = b"", name_type: NameType = NameType.host_name):
        self.name = name
        self.name_type = name_type

    def pack(self) -> bytes:
        return self.name_type.pack() + Vector(2, self.name).pack()

    def unpack(self, data: bytes) -> bytes:
        pass


class ServerNameList(Protocol):
    def __init__(self, server_name_list: typing.Tuple[ServerName, ...]):
        self.server_name_list = server_name_list

    def pack(self) -> bytes:
        return Vector(2, self.server_name_list).pack()

    def unpack(self, data: bytes) -> bytes:
        pass

    @property
    def type(self):
        return ExtensionType.server_name


class Extension(Protocol):
    def __init__(self, protocol: Protocol = None):
        if protocol is None:
            protocol = Vector(2)
        self.ext = protocol
        self.ext_type: ExtensionType = protocol.type

    def pack(self) -> bytes:
        return self.ext_type.pack() + Vector(2, self.ext.pack()).pack()

    @classmethod
    def construct(cls, ext_type: ExtensionType):
        for case in switch(ext_type):
            if case(ExtensionType.supported_versions):
                return SupportedVersions()
            if case(ExtensionType.key_share):
                return KeyShareServerHello()
            if case(ExtensionType.pre_shared_key):
                return PreSharedKeyExtension(SelectedIdentity())
            if case(ExtensionType.early_data):
                return EarlyDataIndication()
            if case():
                return None

    def unpack(self, data: bytes) -> bytes:
        self.ext_type, data = ExtensionType.unpack(data)
        return self.ext.unpack(data)

    @property
    def type(self):
        return self.ext_type
