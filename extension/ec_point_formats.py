from dataclasses import dataclass, field

from reader import Block
from common import HandshakeType

__all__ = ["ECPointFormats"]


@dataclass(frozen=True)
class ECPointFormats:
    ec_point_format: int = field(default=0)

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        return Block(1, "byte", "int", variable=True, after_parse=ECPointFormats).from_byte(byte_seq)
