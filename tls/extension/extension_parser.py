# -*- coding: UTF-8 -*-
from .extension import Extension
from reader.bytes_reader import BytesReader


class ExtensionParser:
    def __init__(self, byte_seq: bytes):
        self.__byte_seq = byte_seq

    @staticmethod
    def parse(self) -> list[Extension]:
        pass
