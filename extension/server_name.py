# -*- coding: UTF-8 -*-
from reader import Blocks, Block
from dataclasses import dataclass, field
from common import HandshakeType


# TODO; 複数のホスト名にも対応する。
@dataclass(frozen=True)
class ServerName:
    name: str
    name_type: int = field(default=0)

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        # 拡張子フィールド（byte_seq引数）には、RFC6066のServerNameListが入っていて、2byteヘッダの可変長
        # ベクトルとして表現されるので、最初にその2バイトを消費する。
        server_name = Blocks([
            Block(2, "byte", "int"),
            Block(1, "byte", "int"),
            Block(2, "byte", "raw", variable=True, after_parse=lambda n: n.decode())
        ], after_parse=lambda _, name_type, name: ServerName(name, name_type)).from_byte(byte_seq)
        return server_name

    def unparse(self, handshake_type: HandshakeType):
        res = b""
        res += self.name_type.to_bytes(1)
        name_raw = self.name.encode()
        name_raw_len = len(name_raw).to_bytes(2)
        res += name_raw_len + name_raw
        return len(res).to_bytes(2) + res
