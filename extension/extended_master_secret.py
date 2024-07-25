from dataclasses import dataclass
from .extension_data import ExtensionData


@dataclass(frozen=True)
class ExtendedMasterSecret(ExtensionData):
    @staticmethod
    def parse(byte_seq: bytes, handshake_type):
        assert byte_seq == b""
        return ExtendedMasterSecret()

    def unparse(self, handshake_type):
        return b""
