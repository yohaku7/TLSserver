from dataclasses import dataclass
from common import HandshakeType, ExtensionType
from .extension_data import ExtensionData


@dataclass(frozen=True)
class EncryptThenMAC(ExtensionData):
    @property
    def type(self) -> ExtensionType:
        return ExtensionType.encrypt_then_mac

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        assert byte_seq == b""
        return EncryptThenMAC()

    def unparse(self, handshake_type: HandshakeType):
        return b""
