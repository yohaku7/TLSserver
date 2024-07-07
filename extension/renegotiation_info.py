from dataclasses import dataclass

from reader import BytesReader


@dataclass
class RenegotiationInfo:
    renegotiated_connection: bytes

    @staticmethod
    def parse(byte_seq: bytes):
        br = BytesReader(byte_seq)
        rec = br.read_variable_length(1, "raw")
        assert br.rest_length == 0
        return RenegotiationInfo(rec)
