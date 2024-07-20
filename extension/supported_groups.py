from dataclasses import dataclass

from common import NamedGroup, HandshakeType, ExtensionType
from reader import Blocks, ListBlock
from .extension_data import ExtensionData


@dataclass(frozen=True)
class SupportedGroups(ExtensionData):
    named_group_list: list[NamedGroup]

    @property
    def type(self) -> ExtensionType:
        return ExtensionType.supported_groups

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        return blocks.from_bytes(byte_seq)

    def unparse(self, handshake_type: HandshakeType):
        return blocks.unparse(self.named_group_list)


blocks = Blocks([ListBlock(2, 2, "byte", "int", variable=True, each_after_parse=NamedGroup)],
                after_parse=SupportedGroups)
