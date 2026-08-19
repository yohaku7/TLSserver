from dataclasses import dataclass
from typing import Callable

from alert import Alert


@dataclass(frozen=True)
class ValidationResult[T]:
    value: T | None
    success: bool
    alert: Alert | None = None

    @classmethod
    def failure(cls, alert: Alert) -> "ValidationResult[None]":
        return cls(
            value=None,
            success=False,
            alert=alert,
        )

    @classmethod
    def success(cls, value: T) -> "ValidationResult[T]":
        return cls(
            value=value,
            success=True,
        )

    def unwrap(self) -> T:
        if not self.success:
            raise ValueError
        return self.value

    def unwrap_or(self, default: T) -> T:
        if not self.success:
            return default
        return self.value

    def ignore(self) -> T:
        """
        バリデーション結果を無視し、内部のオブジェクトを返します。
        :return: 内部のオブジェクト
        """
        return self.value
