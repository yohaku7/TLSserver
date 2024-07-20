from dataclasses import dataclass

from common import ExtensionType
from reader import Block
from .extension_data import ExtensionData

__all__ = ["RecordSizeLimit"]


@dataclass(frozen=True)
class RecordSizeLimit(ExtensionData):
    limit: int

    @property
    def type(self) -> ExtensionType:
        return ExtensionType.record_size_limit

    @staticmethod
    def parse(byte_seq: bytes, handshake_type):
        return block.from_bytes(byte_seq)

    def unparse(self, handshake_type):
        return block.unparse(self.limit)


block = Block(2, "byte", "int", after_parse=lambda x: RecordSizeLimit(x))
