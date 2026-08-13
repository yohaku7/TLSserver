from dataclasses import dataclass

from reader import new
from reader.new import BytesConvertable, BytesConverter


@dataclass(frozen=True)
class ExtendedMasterSecret(new.TLSObject):
    @classmethod
    def _get_lengths(cls) -> list[BytesConverter | BytesConvertable]:
        return []
