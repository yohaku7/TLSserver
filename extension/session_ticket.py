from dataclasses import dataclass
from reader import Block, Blocks
from common import HandshakeType
from .extension_data import ExtensionData

# RFC8447, RFC5077 §3.2 を参照。

__all__ = ["SessionTicket"]


@dataclass(frozen=True)
class SessionTicket(ExtensionData):
    ticket: bytes
    blocks = Blocks([
        Block(2, "raw", variable=True)
    ])

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        if byte_seq == b"":
            return SessionTicket(b"")
        return block.from_bytes(byte_seq)


SessionTicket.blocks.after_parse_factory = SessionTicket
