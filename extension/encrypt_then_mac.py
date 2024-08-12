from dataclasses import dataclass
from reader.new import BytesConverter, BytesConvertable
from reader import new


@dataclass(frozen=True)
class EncryptThenMAC(new.TLSObject):
    @classmethod
    def _get_lengths(cls) -> list[BytesConverter | BytesConvertable]:
        return []
