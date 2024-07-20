from abc import ABC, abstractmethod
from common import HandshakeType, ExtensionType

__all__ = ["ExtensionData"]


class ExtensionData(ABC):
    @property
    @abstractmethod
    def type(self) -> ExtensionType:
        pass

    @staticmethod
    @abstractmethod
    def parse(data: bytes, handshake_type: HandshakeType):
        pass

    @abstractmethod
    def unparse(self, handshake_type: HandshakeType) -> bytes:
        pass
