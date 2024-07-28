from dataclasses import dataclass
from reader import Block, Blocks
from .extension_data import ExtensionData

__all__ = ["RecordSizeLimit"]


@dataclass(frozen=True)
class RecordSizeLimit(ExtensionData):
    limit: int
    blocks = Blocks([
        Block(2, "int")
    ])


RecordSizeLimit.blocks.after_parse_factory = RecordSizeLimit
