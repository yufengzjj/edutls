import typing
import random

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM, ChaCha20Poly1305
from edutls.types import UInt8Enum, Protocol, ProtocolVersion, Vector, PackableInt


class ContentType(UInt8Enum):
    invalid = 0,
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    heartbeat = 24,


class TLSPlaintext(Protocol):
    def __init__(self, content_type: ContentType = ContentType.invalid, data: bytes = b"",
                 legacy_record_version: int = 0x0303):
        self.content_type: ContentType = content_type
        self.legacy_record_version: ProtocolVersion = ProtocolVersion(legacy_record_version)
        self.data = data

    def pack(self) -> bytes:
        data = memoryview(self.data)
        fragments = []
        while True:
            if len(data) > 16384:
                fragments.append(data[:16384])
                data = data[16384:]
            else:
                fragments.append(data)
                break
        return b"".join(
            (
                self.content_type.pack() + self.legacy_record_version.pack() +
                Vector(2, fragment).pack()
                for fragment in fragments
            )
        )

    def unpack(self, data: bytes) -> bytes:
        self.content_type, data = ContentType.unpack(data)
        data = self.legacy_record_version.unpack(data)
        size = PackableInt(2, 0)
        data = size.unpack(data)
        assert len(data) >= size.value, "TLSPlaintext length not match body"
        self.data = data[:size.value]
        return data[size.value:]

    def to_tls_inner_plaintext(self):
        data = self.data
        fragments = []
        while True:
            if len(data) > 16384:
                fragments.append(data[:16384])
                data = data[16384:]
            else:
                fragments.append(data)
                break
        return tuple(TLSInnerPlaintext(self.content_type, fragment) for fragment in fragments)


class TLSInnerPlaintext(Protocol):
    def __init__(self, content_type: ContentType, content: bytes, padding_length: int = 0):
        assert len(content) <= 16384, "TLSInnerPlaintext overflow"
        self.content_type = content_type
        self.content = content
        if padding_length <= -1:
            self.padding = b"\x00" * random.randint(0, (16384 - len(self.content)))
        else:
            self.padding = b"\x00" * padding_length

    def pack(self) -> bytes:
        return self.content + self.content_type.pack() + self.padding

    def unpack(self, data: bytes) -> bytes:
        zero_banner = len(data) - 1
        while zero_banner >= 0:
            if data[zero_banner] == 0:
                zero_banner -= 1
            else:
                zero_banner += 1
                break
        self.padding = data[zero_banner:]
        data = data[:zero_banner]
        self.content_type, none = ContentType.unpack(data[-1:])
        self.content = data[:-1]
        return b""

    def to_tls_plaintext(self):
        return TLSPlaintext(self.content_type, self.content)


class TLSCiphertext(Protocol):
    def __init__(self, write_key: bytes, nonce: bytes,
                 tls_inner_plaintext: TLSInnerPlaintext = None):
        if tls_inner_plaintext is None:
            tls_inner_plaintext = TLSInnerPlaintext(ContentType.invalid, b"", 0)
        self.content_type = ContentType.application_data
        self.legacy_record_version = ProtocolVersion(0x0303)
        self.tls_inner_plaintext = tls_inner_plaintext
        self.write_key = write_key
        self.nonce = nonce
        self.encrypted_record: bytes = tls_inner_plaintext.pack()

    def pack(self) -> bytes:
        return self.content_type.pack() + self.legacy_record_version.pack() + PackableInt(2, len(
            self.encrypted_record)).pack() + self.encrypted_record

    def unpack(self, data: bytes) -> bytes:
        self.content_type, data = ContentType.unpack(data)
        assert self.content_type in (ContentType.application_data, ContentType.change_cipher_spec), \
            f"TLSCiphertext error type:{self.content_type}"
        data = self.legacy_record_version.unpack(data)
        size = PackableInt(2, 0)
        data = size.unpack(data)
        assert len(data) >= size.value, "TLSCiphertext length not match body"
        self.encrypted_record = data[:size.value]
        return data[size.value:]

    def _additional_data(self, expansion_len=0) -> bytes:
        return self.content_type.pack() + self.legacy_record_version.pack() \
               + PackableInt(2, len(self.encrypted_record) + expansion_len).pack()

    def encrypt(self, algorithm: typing.Type[typing.Union[AESGCM, AESCCM, ChaCha20Poly1305]]):
        enc = algorithm(self.write_key)
        self.encrypted_record = enc.encrypt(self.nonce, self.encrypted_record, self._additional_data(16))

    def decrypt(self, algorithm: typing.Type[typing.Union[AESGCM, AESCCM, ChaCha20Poly1305]]):
        dec = algorithm(self.write_key)
        self.encrypted_record = dec.decrypt(self.nonce, self.encrypted_record, self._additional_data())
