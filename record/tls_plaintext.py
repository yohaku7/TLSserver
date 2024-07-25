from .content_type import ContentType
from dataclasses import dataclass
from reader import Blocks, Block, BytesReader
from typing import ClassVar

__all__ = ["TLSPlaintext"]


@dataclass(frozen=True)
class TLSPlaintext:
    type: ContentType
    legacy_record_version: int
    length: int
    blocks: ClassVar[Blocks] = Blocks([
        Block(1, "byte", "int", after_parse=ContentType),
        Block(2, "byte", "int"),
        Block(2, "byte", "int"),
    ])


TLSPlaintext.blocks.after_parse_factory = TLSPlaintext
