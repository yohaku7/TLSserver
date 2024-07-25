from dataclasses import dataclass
from record import ContentType
from reader import BytesReader, Blocks, Block


@dataclass(frozen=True)
class TLSInnerPlaintext:
    content: bytes
    type: ContentType
    zeros: bytes  # zero-padding.

    @staticmethod
    def from_bytes(data: bytes):
        # バイナリの末尾から処理
        data_rev = bytes(reversed(data))
        br = BytesReader(data_rev)
        zeros = b""
        while br.rest_bytes()[0] == b"\x00":  # パディングを取り除く
            zeros += br.read_byte(1, "raw")
        content_type = ContentType(br.read_byte(1, "int"))
        content = br.rest_bytes()
        return TLSInnerPlaintext(content, content_type, zeros)

    def unparse(self):
        return self.content + self.type.to_bytes(1) + self.zeros
