# -*- coding: UTF-8 -*-
from .extension import Extension
from reader.bytes_reader import BytesReader
from .server_name import ExtensionType, ServerName


class ExtensionParser:
    def __init__(self, byte_seq: bytes):
        self.__byte_seq = byte_seq

    @staticmethod
    def parse(byte_seq: bytes) -> list[Extension]:
        extension_list = []
        br = BytesReader(byte_seq)
        while br.rest_bytes() != 0:
            extension_type = br.read_byte(2, "int")
            extension_type = ExtensionType(extension_type)
            ext: Extension
            match extension_type:
                case ExtensionType.server_name:
                    ext = ServerName.parse_br(br)
                    extension_list.append(ext)
                case _:
                    raise ValueError("非対応のExtensionです。")
        return extension_list
