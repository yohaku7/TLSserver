from .content_type import ContentType
from dataclasses import dataclass
from reader import BytesReader


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
