from dataclasses import dataclass

from reader import Blocks, ListBlock
from common import NamedGroup, HandshakeType


@dataclass(frozen=True)
class SupportedGroups:
    named_group_list: list[NamedGroup]

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        supported_groups = Blocks([
            ListBlock(2, 2, "byte", "int", variable=True, each_after_parse=NamedGroup)
        ], after_parse=SupportedGroups).from_byte(byte_seq)
        return supported_groups

    def unparse(self, handshake_type: HandshakeType):
        named_group_raw = b""

        for named_group in self.named_group_list:
            named_group_raw += named_group.value.to_bytes(2)
        return len(named_group_raw).to_bytes(2) + named_group_raw
