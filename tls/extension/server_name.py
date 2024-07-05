# -*- coding: UTF-8 -*-
from reader import BytesReader
from dataclasses import dataclass, field


@dataclass
class ServerName:
    name: str
    name_type: int = field(default=0)

    @staticmethod
    def parse(byte_seq: bytes):
        br = BytesReader(byte_seq)
        name_type = br.read_byte(1, "int")
        assert name_type == 0
        name = br.read_variable_length(2, "raw").decode()

        return ServerName(name, name_type=name_type)

    @staticmethod
    def unparse(byte_seq: bytes):
        pass
