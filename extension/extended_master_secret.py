from dataclasses import dataclass


@dataclass
class ExtendedMasterSecret:
    @staticmethod
    def parse(byte_seq: bytes, handshake_type):
        assert byte_seq is None
        return ExtendedMasterSecret()

    def unparse(self, handshake_type):
        return b""
