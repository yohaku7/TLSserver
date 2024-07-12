from .content_type import ContentType
from dataclasses import dataclass
from reader import BytesReader, BytesBuilder


@dataclass
class TLSPlaintext:
    type: ContentType
    legacy_record_version: int
    length: int
    fragment: bytes

    @staticmethod
    def parse(byte_seq: bytes):
        br = BytesReader(byte_seq)
        type = br.read_byte(1, "int")
        lrv = br.read_byte(2, "int")
        length = br.read_byte(2, "int")
        fragment = br.rest_bytes()
        return TLSPlaintext(ContentType(type), lrv, length, fragment)

    def unparse(self):
        bb = BytesBuilder()
        bb.append_int(self.type.value, 1)
        bb.append_int(self.legacy_record_version, 2)
        bb.append_int(self.length, 2)
        bb.append(self.fragment)
        return bb.to_bytes()
