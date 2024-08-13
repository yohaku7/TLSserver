from tls_object import TLSIntEnum
from reader import new
from dataclasses import dataclass
from enum import IntEnum


# Reference: RFC8446 §4.2.9


class PskKeyExchangeMode(TLSIntEnum, IntEnum):
    psk_ke = 0
    psk_dhe_ke = 1

    @classmethod
    def byte_length(cls) -> int:
        return 1


@dataclass(frozen=True)
class PskKeyExchangeModes(new.TLSObject):
    ke_modes: PskKeyExchangeMode

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            (1, True)
        ]

    def reply(self):
        assert self.ke_modes == PskKeyExchangeMode.psk_dhe_ke
