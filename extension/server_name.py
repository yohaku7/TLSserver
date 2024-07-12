# -*- coding: UTF-8 -*-
from reader import BytesReader
from dataclasses import dataclass, field
from common import HandshakeType


# TODO; 複数のホスト名にも対応する。
@dataclass
class ServerName:
    name: str
    name_type: int = field(default=0)

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        br = BytesReader(byte_seq)
        # 拡張子フィールド（byte_seq引数）には、RFC6066のServerNameListが入っていて、2byteヘッダの可変長
        # ベクトルとして表現されるので、最初にその2バイトを消費する。
        _ = br.i(0, 2)
        name_type = br.i(0, 1)
        assert name_type == 0
        name = br.read_variable_length(2, "raw").decode()

        return ServerName(name, name_type=name_type)

    def unparse(self, handshake_type: HandshakeType):
        res = b""
        res += self.name_type.to_bytes(1)
        name_raw = self.name.encode()
        name_raw_len = len(name_raw).to_bytes(2)
        res += name_raw_len + name_raw
        return len(res).to_bytes(2) + res
