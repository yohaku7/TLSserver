from dataclasses import dataclass
from reader import BytesReader


@dataclass
class RecordSizeLimit:
    limit: int

    @staticmethod
    def parse(byte_seq: bytes, handshake_type):
        br = BytesReader(byte_seq)
        return RecordSizeLimit(br.i(0, 2))

    def unparse(self, handshake_type):
        return self.limit.to_bytes(2)
