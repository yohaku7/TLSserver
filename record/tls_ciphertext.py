from common import ContentType
from dataclasses import dataclass
from reader import new


@dataclass(frozen=True)
class TLSCiphertext(new.TLSObject):
    opaque_type: ContentType
    legacy_record_version: int
    length: int
    encrypted_record: bytes

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            1,
            2,
            2,
            -1
        ]
