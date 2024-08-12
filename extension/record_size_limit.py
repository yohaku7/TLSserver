from dataclasses import dataclass
from reader import new
from reader.new import BytesConverter, BytesConvertable

__all__ = ["RecordSizeLimit"]


@dataclass(frozen=True)
class RecordSizeLimit(new.TLSObject):
    limit: int

    @classmethod
    def _get_lengths(cls) -> list[BytesConverter | BytesConvertable]:
        return [
            new.Block(2)
        ]
