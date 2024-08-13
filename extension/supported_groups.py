from dataclasses import dataclass
from common import NamedGroup
from reader import new
from .extension_data import ExtensionReply


@dataclass(frozen=True)
class SupportedGroups(new.TLSObject):
    named_group_list: list[NamedGroup]

    def reply(self) -> ExtensionReply:
        assert NamedGroup.x25519 in self.named_group_list
        return ExtensionReply(f"Supported Groups: {NamedGroup.x25519}")

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            (2, True, 2)
        ]
