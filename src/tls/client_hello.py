# -*- coding: UTF-8 -*-
# RFC8446 §4.1.2 に基づいたClientHelloとエンコードされた実際のメッセージ（バイト列）。
from dataclasses import dataclass
from src.reader.bytes_reader import BytesReader


@dataclass
class ClientHello:
    legacy_version: int  # uint16; 16bit unsigned int
    random: int  # 32byte integer
    legacy_session_id: bytes
    cipher_suites: bytes
    legacy_compression_methods: bytes
    extensions: bytes


class ClientHelloReader:
    def __init__(self, byte_seq: bytes):
        self.__bytes_reader = BytesReader(byte_seq)

    def __parse(self):
        legacy_version = self.__bytes_reader.read_byte(2, "int")
        random = self.__bytes_reader.read_byte(32, "int")
        legacy_session_id = self.__bytes_reader.read_variable_length(1, "int")

