# -*- coding: UTF-8 -*-
from reader import BytesReader
from dataclasses import dataclass, field


# TODO; 複数のホスト名にも対応する。
@dataclass
class ServerName:
    name: str
    name_type: int = field(default=0)

    @staticmethod
    def parse(byte_seq: bytes):
        br = BytesReader(byte_seq)
        # 拡張子フィールド（byte_seq引数）には、RFC6066のServerNameListが入っていて、2byteヘッダの可変長
        # ベクトルとして表現されるので、最初にその2バイトを消費する。
        _ = br.read_byte(2, "int")
        name_type = br.read_byte(1, "int")
        assert name_type == 0
        name = br.read_variable_length(2, "raw").decode()

        return ServerName(name, name_type=name_type)

    @staticmethod
    def unparse(sn: "ServerName"):
        pass
