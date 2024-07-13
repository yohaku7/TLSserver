from dataclasses import dataclass

from reader import Block
from common import HandshakeType


@dataclass
class SessionTicket:
    ticket: bytes | None

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        if byte_seq == b"":
            return SessionTicket(b"")
        return Block(2, "byte", "raw", True, after_parse=SessionTicket).from_byte(byte_seq)
