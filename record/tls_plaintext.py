from .content_type import ContentType
from dataclasses import dataclass
from reader import BytesReader, BytesBuilder

from handshake import Handshake
from alert import Alert


@dataclass(frozen=True)
class TLSPlaintext:
    type: ContentType
    legacy_record_version: int
    length: int
    fragment: object

    @staticmethod
    def parse(byte_seq: bytes):
        br = BytesReader(byte_seq)
        type = br.read_byte(1, "int")
        lrv = br.read_byte(2, "int")
        length = br.read_byte(2, "int")

        match type:
            case ContentType.handshake:
                fragment = Handshake.parse(br.rest_bytes())
            case ContentType.alert:
                fragment = Alert.parse(br.rest_bytes())
            case _:
                raise ValueError("対応してないContentTypeだよ！")

        return TLSPlaintext(ContentType(type), lrv, length, fragment)

    @staticmethod
    def make(type: ContentType, fragment: object):
        fragment_raw = fragment.unparse()
        return TLSPlaintext(
            type=type,
            legacy_record_version=0x0303,
            length=len(fragment_raw),
            fragment=fragment
        )

    def unparse(self):
        bb = BytesBuilder()
        bb.append_int(self.type.value, 1)
        bb.append_int(self.legacy_record_version, 2)
        bb.append_int(self.length, 2)
        bb.append(self.fragment.unparse())
        return bb.to_bytes()
