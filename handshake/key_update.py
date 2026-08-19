from dataclasses import dataclass
from enum import IntEnum

from alert import Alert, AlertLevel, AlertDescription
from reader.validation_result import ValidationResult


__all__ = ["TLSKeyUpdate", "KeyUpdateRequest"]


class KeyUpdateRequest(IntEnum):
    update_not_requested = 0
    update_requested = 1

@dataclass(frozen=True)
class TLSKeyUpdate:
    request_update: int

    @classmethod
    def from_bytes(cls, data: bytes):
        return TLSKeyUpdate(int.from_bytes(data, byteorder="big"))

    def to_bytes(self) -> bytes:
        return int.to_bytes(self.request_update, 1, "big")

    def validate(self) -> ValidationResult["TLSKeyUpdate"]:
        if self.request_update not in KeyUpdateRequest:
            return ValidationResult.failure(
                Alert(AlertLevel.fatal, AlertDescription.illegal_parameter)
            )
        return ValidationResult.success(self)
