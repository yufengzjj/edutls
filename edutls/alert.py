from edutls.record import ContentType
from edutls.types import UInt8Enum, UInt16Enum, Protocol


class AlertLevel(UInt8Enum):
    warning = 1,
    fatal = 2


class AlertDescription(UInt8Enum):
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    record_overflow = 22,
    handshake_failure = 40,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    inappropriate_fallback = 86,
    user_canceled = 90,
    missing_extension = 109,
    unsupported_extension = 110,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,


class Alert(Protocol):
    def __init__(self, level: AlertLevel = AlertLevel.warning,
                 description: AlertDescription = AlertDescription.close_notify):
        self.level = level
        self.description = description

    def pack(self) -> bytes:
        return self.level.pack() + self.description.pack()

    def unpack(self, data: bytes) -> bytes:
        self.level, data = AlertLevel.unpack(data)
        self.description, data = AlertDescription.unpack(data)
        return data

    @property
    def type(self):
        return ContentType.alert
