from dataclasses import dataclass
from reader import new
from reader.new import BytesConverter, BytesConvertable


@dataclass(frozen=True)
class RenegotiationInfo(new.TLSObject):
    renegotiated_connection: bytes

    @classmethod
    def _get_lengths(cls) -> list[BytesConverter | BytesConvertable]:
        return [
            new.Block(new.Variable(1))
        ]
