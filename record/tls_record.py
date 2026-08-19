from dataclasses import dataclass

from alert import Alert, AlertLevel, AlertDescription

__all__ = ["TLSRecordHeader"]

from common import ContentType

from reader.validation_result import ValidationResult


@dataclass(frozen=True)
class TLSRecordHeader:
    content_type: int
    legacy_record_version: int
    length: int

    @classmethod
    def from_bytes(cls, data: bytes):
        return TLSRecordHeader(
            content_type=int.from_bytes(data[0:1], byteorder="big"),
            legacy_record_version=int.from_bytes(data[1:3], byteorder="big"),
            length=int.from_bytes(data[3:5], byteorder="big"),
        )

    def to_bytes(self) -> bytes:
        return (int.to_bytes(self.content_type, 1)
                + int.to_bytes(self.legacy_record_version, 2)
                + int.to_bytes(self.length, 2))

    def validate(self) -> ValidationResult["TLSRecordHeader"]:
        if self.content_type not in ContentType:
            return ValidationResult.failure(
                Alert(AlertLevel.fatal, AlertDescription.illegal_parameter)
            )

        # refer: RFC8446 §5.1
        if self.length > 2 ** 14:
            return ValidationResult.failure(
                Alert(AlertLevel.fatal, AlertDescription.record_overflow)
            )
        return ValidationResult.success(self)
