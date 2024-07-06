from dataclasses import dataclass, field
from enum import IntEnum

from reader import BytesReader


class NamedGroup(IntEnum):
    # ECDHE
    secp256r1 = 0x0017
    secp384r1 = 0x0018
    secp521r1 = 0x0019
    x25519    = 0x001d
    x448      = 0x001e

    # DHE
    ffdhe2048 = 0x0100
    ffdhe3072 = 0x0101
    ffdhe4096 = 0x0102
    ffdhe6144 = 0x0103
    ffdhe8192 = 0x0104

    # 0xffff

@dataclass
class SupportedGroups:
    named_group_list: list[NamedGroup]

    @staticmethod
    def parse(byte_seq: bytes):
        br = BytesReader(byte_seq)
        named_group_list = br.read_variable_length_per(2, 2, "int")
        named_group_list = list(map(NamedGroup, named_group_list))
        return SupportedGroups(named_group_list)
