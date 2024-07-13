from dataclasses import dataclass
from common import HandshakeType


@dataclass
class EncryptThenMAC:
    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        assert byte_seq == b""
        return EncryptThenMAC()

    def unparse(self, handshake_type: HandshakeType):
        return b""
