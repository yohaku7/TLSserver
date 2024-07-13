from enum import IntEnum
from dataclasses import dataclass
from reader import BytesBuilder, Block


class PskKeyExchangeMode(IntEnum):
    psk_ke = 0
    psk_dhe_ke = 1
    # 255


@dataclass
class PskKeyExchangeModes:
    ke_modes: PskKeyExchangeMode

    @staticmethod
    def parse(byte_seq: bytes, handshake_type):
        return Block(1, "byte", "int", True,
                     after_parse=lambda ke_modes: PskKeyExchangeModes(PskKeyExchangeMode(ke_modes))).from_byte(byte_seq)

    def unparse(self, handshake_type):
        bb = BytesBuilder()
        bb.append_variable_length(1, self.ke_modes.value.to_bytes(1))
        return bb.to_bytes()
