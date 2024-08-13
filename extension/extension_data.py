from dataclasses import dataclass, field
from typing import Any

__all__ = ["ExtensionReply"]


@dataclass
class ExtensionReply:
    message: str
    obj: Any | None = field(default=None)
