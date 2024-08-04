from common import ContentType
from dataclasses import dataclass
from reader import Blocks, Block, BytesReader, EnumBlock, RestBlock
from typing import ClassVar

__all__ = ["TLSPlaintext"]

from .tls_record import TLSRecord
from .tls_record_obj import TLSRecordObj
from handshake import Handshake
from alert import Alert


content_types: dict[type[TLSRecordObj], ContentType] = {
    Handshake: ContentType.handshake,
    Alert: ContentType.alert,
}


@dataclass(frozen=True)
class TLSPlaintext(TLSRecord):
    type: ContentType
    legacy_record_version: int
    length: int
    fragment: bytes

    blocks: ClassVar[Blocks] = Blocks([
        EnumBlock(ContentType),
        Block(2, "int"),
        Block(2, "int"),
        RestBlock("raw"),
    ])

    @staticmethod
    def make(obj: TLSRecordObj):
        if not type(obj) in content_types:
            raise ValueError("TLSRecordObjをパースできません")
        c_type = content_types[type(obj)]
        lr_version = 0x0303
        fragment = obj.blocks.unparse(obj)
        length = len(fragment)
        return TLSPlaintext(c_type, lr_version, length, fragment)

    def unparse(self):
        return self.blocks.unparse(self)

TLSPlaintext.blocks.after_parse_factory = TLSPlaintext
