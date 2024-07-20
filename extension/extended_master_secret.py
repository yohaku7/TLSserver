from dataclasses import dataclass

from common import ExtensionType
from .extension_data import ExtensionData


@dataclass(frozen=True)
class ExtendedMasterSecret(ExtensionData):
    @property
    def type(self) -> ExtensionType:
        return ExtensionType.extended_master_secret

    @staticmethod
    def parse(byte_seq: bytes, handshake_type):
        assert byte_seq == b""
        return ExtendedMasterSecret()

    def unparse(self, handshake_type):
        return b""
