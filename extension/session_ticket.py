from dataclasses import dataclass

from reader import BytesReader
from common import HandshakeType


@dataclass
class SessionTicket:
    ticket: bytes | None

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        if byte_seq is None:
            return SessionTicket(None)
        br = BytesReader(byte_seq)
        return SessionTicket(br.read_variable_length(2, "raw"))
