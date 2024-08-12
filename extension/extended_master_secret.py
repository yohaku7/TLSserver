from dataclasses import dataclass
from reader import new
from reader.new import BytesConverter, BytesConvertable


@dataclass(frozen=True)
class ExtendedMasterSecret(new.TLSObject):
    @classmethod
    def _get_lengths(cls) -> list[BytesConverter | BytesConvertable]:
        return []
