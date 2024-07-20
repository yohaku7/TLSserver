from .content_type import ContentType
from dataclasses import dataclass
from reader import Blocks, Block, RestBlock

from handshake import Handshake
from alert import Alert

__all__ = ["TLSPlaintext"]


def _make(content_type, legacy_record_version, length, fragment_raw):
    match content_type:
        case ContentType.handshake:
            fragment = Handshake.parse(fragment_raw)
        case ContentType.alert:
            fragment = Alert.parse(fragment_raw)
        case _:
            raise ValueError("対応してないContentTypeだよ！")
    return TLSPlaintext(
        content_type, legacy_record_version, length,
        fragment
    )


@dataclass(frozen=True)
class TLSPlaintext:
    type: ContentType
    legacy_record_version: int
    length: int
    fragment: object

    @staticmethod
    def parse(byte_seq: bytes):
        return _blocks.from_bytes(byte_seq)

    def unparse(self):
        return _blocks.unparse(
            self.type.value, self.legacy_record_version, self.length,
            self.fragment.unparse()
        )


_blocks = Blocks([
    Block(1, "byte", "int", after_parse=ContentType),
    Block(2, "byte", "int"),
    Block(2, "byte", "int"),
    RestBlock("raw")
], after_parse=_make)
