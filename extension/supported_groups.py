from dataclasses import dataclass

from reader import BytesReader
from common import NamedGroup


@dataclass
class SupportedGroups:
    named_group_list: list[NamedGroup]

    @staticmethod
    def parse(byte_seq: bytes):
        br = BytesReader(byte_seq)
        named_group_list = br.read_variable_length_per(2, 2, "int")
        named_group_list = list(map(NamedGroup, named_group_list))
        return SupportedGroups(named_group_list)
