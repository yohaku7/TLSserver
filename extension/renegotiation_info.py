from dataclasses import dataclass
from reader import new


@dataclass(frozen=True)
class RenegotiationInfo(new.TLSObject):
    renegotiated_connection: bytes

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            1
        ]
