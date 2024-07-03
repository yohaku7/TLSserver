# -*- coding: UTF-8 -*-
from . import Extension, ExtensionType
from reader import BytesReader
from dataclasses import dataclass


@dataclass
class ServerName(Extension):
    @staticmethod
    def parse(byte_seq: bytes) -> "ServerName":
        extension_type = 0
        br = BytesReader(byte_seq)
        server_name_list = br.read_variable_length(2, "hex")

    @staticmethod
    def parse_br(br: BytesReader) -> "ServerName":
        extension_type = ExtensionType.server_name
        server_name_list = br.read_variable_length(2, "raw")
        return ServerName(extension_type, server_name_list)
