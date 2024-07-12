from dataclasses import dataclass

from reader import BytesReader
from common import NamedGroup, HandshakeType


@dataclass
class SupportedGroups:
    named_group_list: list[NamedGroup]

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        br = BytesReader(byte_seq)
        named_group_list = br.i(0x21, 2, per=2)
        named_group_list = list(map(NamedGroup, named_group_list))
        return SupportedGroups(named_group_list)

    def unparse(self, handshake_type: HandshakeType):
        named_group_raw = b""

        for named_group in self.named_group_list:
            named_group_raw += named_group.value.to_bytes(2)
        return len(named_group_raw).to_bytes(2) + named_group_raw
