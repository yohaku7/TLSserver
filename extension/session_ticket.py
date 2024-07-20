from dataclasses import dataclass

from reader import Block
from common import HandshakeType, ExtensionType
from .extension_data import ExtensionData

# RFC8447, RFC5077 §3.2 を参照。

__all__ = ["SessionTicket"]


@dataclass(frozen=True)
class SessionTicket(ExtensionData):
    ticket: bytes

    @property
    def type(self) -> ExtensionType:
        return ExtensionType.session_ticket

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        if byte_seq == b"":
            return SessionTicket(b"")
        return block.from_bytes(byte_seq)

    def unparse(self, handshake_type: HandshakeType):
        return block.unparse(self.ticket)


block = Block(2, "byte", "raw", variable=True, after_parse=lambda x: SessionTicket(x))
