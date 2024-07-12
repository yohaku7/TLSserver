from dataclasses import dataclass, field

from reader import BytesReader
from common import HandshakeType


@dataclass
class ECPointFormats:
    ec_point_format: int = field(default=0)

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        br = BytesReader(byte_seq)
        return ECPointFormats(br.i(0x20, 1))
