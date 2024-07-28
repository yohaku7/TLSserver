from tls_object import TLSIntEnum
from reader import Blocks, EnumBlock
from .extension_data import ExtensionData, ExtensionReply
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
class PskKeyExchangeModes(ExtensionData):
    ke_modes: PskKeyExchangeMode
    blocks = Blocks([
        EnumBlock(PskKeyExchangeMode, variable=True, variable_header_size=1)
    ])

    def reply(self) -> ExtensionReply:
        assert self.ke_modes == PskKeyExchangeMode.psk_dhe_ke


PskKeyExchangeModes.blocks.after_parse_factory = PskKeyExchangeModes
