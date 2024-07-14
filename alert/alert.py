from dataclasses import dataclass
from enum import IntEnum
from typing import ClassVar

from reader import BytesBuilder, Blocks, Block

__all__ = ["AlertLevel", "Alert"]


class AlertLevel(IntEnum):
    warning = 1
    fatal = 2
    # 255


class AlertDescription(IntEnum):
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
    # 255


@dataclass(frozen=True)
class Alert:
    level: AlertLevel
    description: AlertDescription
    blocks: ClassVar[Blocks] = Blocks([
        Block(1, "byte", "int", after_parse=AlertLevel),
        Block(1, "byte", "int", after_parse=AlertDescription)
    ], after_parse=lambda level, desc: Alert(level, desc))

    @staticmethod
    def parse(byte_seq: bytes):
        return Alert.blocks.from_byte(byte_seq)

    def unparse(self):
        bb = BytesBuilder()
        bb.append_int(self.level.value, 1)
        bb.append_int(self.description.value, 1)
        return bb.to_bytes()
