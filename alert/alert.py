from dataclasses import dataclass
from enum import IntEnum
from reader.new import BytesConverter, BytesConvertable
from tls_object import TLSIntEnum
from reader import new


__all__ = ["AlertLevel", "Alert"]


class AlertLevel(TLSIntEnum, IntEnum):
    warning = 1
    fatal = 2

    @classmethod
    def byte_length(cls) -> int:
        return 1


class AlertDescription(TLSIntEnum, IntEnum):
    close_notify = 0
    unexpected_message = 10
    bad_record_mac = 20
    record_overflow = 22
    handshake_failure = 40
    bad_certificate = 42
    unsupported_certificate = 43
    certificate_revoked = 44
    certificate_expired = 45
    certificate_unknown = 46
    illegal_parameter = 47
    unknown_ca = 48
    access_denied = 49
    decode_error = 50
    decrypt_error = 51
    protocol_version = 70
    insufficient_security = 71
    internal_error = 80
    inappropriate_fallback = 86
    user_canceled = 90
    missing_extension = 109
    unsupported_extension = 110
    unrecognized_name = 112
    bad_certificate_status_response = 113
    unknown_psk_identity = 115
    certificate_required = 116
    no_application_protocol = 120

    @classmethod
    def byte_length(cls) -> int:
        return 1


@dataclass(frozen=True)
class Alert(new.TLSObject):
    level: AlertLevel
    description: AlertDescription

    @classmethod
    def _get_lengths(cls) -> list[BytesConverter | BytesConvertable]:
        return [
            new.Block(1),
            new.Block(1)
        ]
