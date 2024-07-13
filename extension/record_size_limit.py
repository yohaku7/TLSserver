from dataclasses import dataclass
from reader import Block


@dataclass
class RecordSizeLimit:
    limit: int

    @staticmethod
    def parse(byte_seq: bytes, handshake_type):
        return Block(2, "byte", "int", after_parse=RecordSizeLimit).from_byte(byte_seq)

    def unparse(self, handshake_type):
        return self.limit.to_bytes(2)
