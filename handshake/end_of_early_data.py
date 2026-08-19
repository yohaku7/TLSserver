from dataclasses import dataclass

from reader import new


__all__ = ["EndOfEarlyData"]


@dataclass(frozen=True)
class EndOfEarlyData(new.TLSObject):
    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return []
