from dataclasses import dataclass


@dataclass(frozen=True)
class ExtendedMasterSecret:
    @staticmethod
    def parse(byte_seq: bytes, handshake_type):
        assert byte_seq == b""
        return ExtendedMasterSecret()

    def unparse(self, handshake_type):
        return b""
