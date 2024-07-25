from enum import IntEnum
from reader import Blocks, EnumBlock
from .extension_data import ExtensionData, ExtensionReply
from dataclasses import dataclass


# Reference: RFC8446 §4.2.9


class PskKeyExchangeMode(IntEnum):
    psk_ke = 0
    psk_dhe_ke = 1
    # 255


@dataclass(frozen=True)
class PskKeyExchangeModes(ExtensionData):
    ke_modes: PskKeyExchangeMode
    blocks = Blocks([
        EnumBlock(1, PskKeyExchangeMode, variable=True)
    ])

    def reply(self) -> ExtensionReply:
        assert self.ke_modes == PskKeyExchangeMode.psk_dhe_ke



PskKeyExchangeModes.blocks.after_parse_factory = PskKeyExchangeModes
