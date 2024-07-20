from dataclasses import dataclass

from reader import Block
from common import HandshakeType, ExtensionType
from .extension_data import ExtensionData


@dataclass(frozen=True)
class RenegotiationInfo(ExtensionData):
    renegotiated_connection: bytes

    @property
    def type(self) -> ExtensionType:
        return ExtensionType.renegotiation_info

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        return block.from_bytes(byte_seq)

    def unparse(self, handshake_type: HandshakeType) -> bytes:
        return block.unparse(self.renegotiated_connection)


block = Block(1, "byte", "raw", variable=True, after_parse=lambda x: RenegotiationInfo(x))
