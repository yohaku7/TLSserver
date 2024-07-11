from dataclasses import dataclass, field

from reader import BytesReader
from common import HandshakeType


@dataclass
class ECPointFormats:
    ec_point_format: int = field(default=0)

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        br = BytesReader(byte_seq)
        ec_point_format = br.read_variable_length(1, "int")
        return ECPointFormats(ec_point_format)
