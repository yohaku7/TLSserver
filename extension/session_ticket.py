from dataclasses import dataclass
from reader import Block, Blocks
from common import HandshakeType
from .extension_data import ExtensionData

# RFC8447, RFC5077 §3.2 を参照。

__all__ = ["SessionTicket"]


"""
If the client does not have a ticket and is prepared to receive one in the NewSessionTicket handshake message,
then it MUST include a zero-length ticket in the SessionTicket extension.
"""


@dataclass(frozen=True)
class SessionTicket(ExtensionData):
    ticket: bytes

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        if byte_seq == b"":
            return SessionTicket(b"")
        return SessionTicket.blocks.from_bytes(byte_seq)

    def unparse(self, handshake_type: HandshakeType) -> bytes:
        return b""
