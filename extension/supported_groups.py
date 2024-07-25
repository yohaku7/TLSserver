from dataclasses import dataclass
from common import NamedGroup
from reader import Blocks, EnumListBlock
from .extension_data import ExtensionData, ExtensionReply


@dataclass(frozen=True)
class SupportedGroups(ExtensionData):
    named_group_list: list[NamedGroup]
    blocks = Blocks([
        EnumListBlock(2, 2, NamedGroup, variable=True)
    ])

    def reply(self) -> ExtensionReply:
        assert NamedGroup.x25519 in self.named_group_list
        return ExtensionReply(f"Supported Groups: {NamedGroup.x25519}")


SupportedGroups.blocks.after_parse_factory = SupportedGroups
