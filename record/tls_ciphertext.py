from .content_type import ContentType
from dataclasses import dataclass
from typing import ClassVar
from reader import Blocks, Block, EnumBlock, RestBlock


@dataclass(frozen=True)
class TLSCiphertext:
    opaque_type: ContentType
    legacy_record_version: int
    length: int
    encrypted_record: bytes
    blocks: ClassVar[Blocks] = Blocks([
        EnumBlock(ContentType),
        Block(2, "int"),
        Block(2, "int"),
        RestBlock("raw")
    ])


TLSCiphertext.blocks.after_parse_factory = TLSCiphertext
