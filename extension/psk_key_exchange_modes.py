from enum import IntEnum
from dataclasses import dataclass

from common import ExtensionType
from reader import Block
from .extension_data import ExtensionData


# Reference: RFC8446 §4.2.9


class PskKeyExchangeMode(IntEnum):
    psk_ke = 0
    psk_dhe_ke = 1
    # 255


@dataclass(frozen=True)
class PskKeyExchangeModes(ExtensionData):
    ke_modes: PskKeyExchangeMode

    @property
    def type(self) -> ExtensionType:
        return ExtensionType.psk_key_exchange_modes

    @staticmethod
    def parse(byte_seq: bytes, handshake_type):
        return block.from_bytes(byte_seq)

    def unparse(self, handshake_type):
        return block.unparse(self.ke_modes)


block = Block(1, "byte", "int", variable=True,
              after_parse=lambda ke_modes: PskKeyExchangeModes(PskKeyExchangeMode(ke_modes)))
