from dataclasses import dataclass

from common import NamedGroup
from reader import new


@dataclass(frozen=True)
class SupportedGroups(new.TLSObject):
    named_group_list: list[NamedGroup]

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            (2, True, 2)
        ]
