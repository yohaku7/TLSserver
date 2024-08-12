# -*- coding: UTF-8 -*-
# written by yohaku7
from ._types import _Base


__all__ = [
    "BytesReader"
]


class BytesReader:
    """バイト列を加工したり、数値を読み取ったりするクラス。"""
    def __init__(self, data: bytes):
        self.__data = data
        self.__length = len(self.__data)
        self.__next_pos = 0

    @property
    def rest_length(self):
        return len(self.rest_bytes())

    def __next_bytes(self, n: int) -> bytes:
        res = self.__data[self.__next_pos:self.__next_pos + n]
        self.__next_pos += n
        return res

    def convert_base(self, data: bytes, base: _Base):
        if base == "raw":
            return data
        if base == "int":
            return int.from_bytes(data)
        if base == "utf8":
            return data.decode()
        raise NotImplementedError

    def read(self, block):
        return block.parse(self)

    def read_byte(self, n: int, base: _Base):
        """nバイト、バイト列を読み、数値として返す"""
        self.__check_byte_length(n)
        res = self.__next_bytes(n)
        return self.convert_base(res, base)

    def read_variable_length(self, length_header_size: int, base: _Base) -> str | int | bytes | None:
        """可変長ベクトルの長さを読み、本体を読む"""
        vector_len = self.read_byte(length_header_size, "int")
        if vector_len == 0:  # 空ベクトル
            return b""
        self.__check_byte_length(vector_len)
        res = self.__next_bytes(vector_len)
        return self.convert_base(res, base)

    def read_variable_length_per(self, length_header_size: int, per: int, base: _Base) \
            -> list[str | int | bytes] | None:
        raw = self.read_variable_length(length_header_size, "raw")
        res = []
        for i in range(0, len(raw), per):
            byte = raw[i:i + per]
            res.append(self.convert_base(byte, base))
        return res

    def rest_bytes(self) -> bytes:
        return self.__data[self.__next_pos:]

    def read_rest_bytes(self, base: _Base) -> bytes:
        res = self.convert_base(self.__data[self.__next_pos:], base)
        self.__next_pos = self.__length
        return res

    def __check_byte_length(self, n: int):
        if n < 0:
            raise ValueError("0byte以上の数値を指定してください。")
        if self.__length < self.__next_pos + n:
            raise EOFError("これ以上読み進められません。")
