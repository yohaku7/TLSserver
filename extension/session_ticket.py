from dataclasses import dataclass

from reader import BytesReader
from common import HandshakeType


@dataclass
class SessionTicket:
    ticket: bytes | None

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        if byte_seq is None:
            return SessionTicket(b"")
        br = BytesReader(byte_seq)
        return SessionTicket(br.r(0x20, 2))
