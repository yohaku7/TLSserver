from dataclasses import dataclass

from reader import BytesBuilder, Block
from common import HandshakeType


@dataclass
class RenegotiationInfo:
    renegotiated_connection: bytes

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        return Block(1, "byte", "raw", True, after_parse=RenegotiationInfo).from_byte(byte_seq)
