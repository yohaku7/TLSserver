from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from typing import ClassVar, Any
from common import HandshakeType
from reader import Blocks

__all__ = ["ExtensionData", "ExtensionReply"]


@dataclass
class ExtensionReply:
    message: str
    obj: Any | None = field(default=None)


class ExtensionData(ABC):
    blocks: ClassVar[Blocks] = None

    @staticmethod
    def parse(data: bytes, handshake_type: HandshakeType):
        raise NotImplementedError("HandshakeTypeによって処理は変化しないので、parseは呼び出されるべきではありません。")

    def unparse(self, handshake_type: HandshakeType) -> bytes:
        raise NotImplementedError("HandshakeTypeによって処理は変化しないので、unparseは呼び出されるべきではありません。")

    def reply(self) -> ExtensionReply:
        pass
