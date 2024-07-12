from enum import IntEnum
from dataclasses import dataclass
from reader import BytesReader, BytesBuilder


class PskKeyExchangeMode(IntEnum):
    psk_ke = 0
    psk_dhe_ke = 1
    # 255


@dataclass
class PskKeyExchangeModes:
    ke_modes: PskKeyExchangeMode

    @staticmethod
    def parse(byte_seq: bytes, handshake_type):
        br = BytesReader(byte_seq)
        # ke_modes = br.read_variable_length(1, "int")
        # ke_modes = PskKeyExchangeMode(ke_modes)
        # return PskKeyExchangeModes(PskKeyExchangeMode(br.read((0x20, 1, "int"))))
        return PskKeyExchangeModes(PskKeyExchangeMode(br.i(0x20, 1)))

    def unparse(self, handshake_type):
        bb = BytesBuilder()
        bb.append_variable_length(1, self.ke_modes.value.to_bytes(1))
        return bb.to_bytes()
