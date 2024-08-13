from dataclasses import dataclass
from reader import new

__all__ = ["RecordSizeLimit"]


@dataclass(frozen=True)
class RecordSizeLimit(new.TLSObject):
    limit: int

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            2
        ]
