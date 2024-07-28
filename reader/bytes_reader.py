# -*- coding: UTF-8 -*-
# written by yohaku7
from __future__ import annotations

from Crypto.Util.number import long_to_bytes
from ._types import _Base


__all__ = [
    "BytesReader"
]


class BytesReader:
    """バイト列を加工したり、数値を読み取ったりするクラス。"""

    def __init__(self, byte_seq: bytes):
        self.__byte_seq = byte_seq
        self.__bin_seq: str = format(int(byte_seq.hex(), 16), f"0{len(byte_seq) * 8}b")
        self.__bin_length = len(self.__bin_seq)
        self.__bin_next_pos = 0

    @property
    def rest_length(self):
        return len(self.rest_bytes())

    def __next_bits(self, n: int) -> str:
        res = self.__bin_seq[self.__bin_next_pos:self.__bin_next_pos + n]
        self.__bin_next_pos += n
        return res

    def __convert_base(self, binary: str, base: _Base, *, byte_len: int | None = None):
        if base == "raw":
            byte_len = 0 if byte_len is None else byte_len
            return long_to_bytes(int(binary, 2), byte_len)
        if base == "bin":
            return binary
        if base == "dec":
            return str(int(binary, 2))
        if base == "hex":
            return format(int(binary, 2), "x")
        if base == "int":
            return int(binary, 2)
        if base == "utf8":
            assert byte_len is not None
            return int(binary, 2).to_bytes(length=byte_len, byteorder="big").decode("utf-8")

    def read(self, block):
        return block.parse(self)

    def read_bit(self, n: int, base: _Base) -> int | str | bytes:
        """nビット、バイト列を読み、数値として返す"""
        self.__check_length(n)
        res = self.__next_bits(n)
        return self.__convert_base(res, base)

    def read_bit_per(self, n: int, per: int, base: _Base) -> list[str | int | bytes]:
        raw = self.read_bit(n, "bin")
        res = []
        for i in range(0, len(raw), per):
            binary = raw[i:i + per]
            res.append(self.__convert_base(binary, base))
        return res

    def read_byte_per(self, n: int, per: int, base: _Base) -> list[str | int | bytes]:
        raw = self.read_byte(n, "raw")
        res = []
        for i in range(0, len(raw), per):
            raw_i = raw[i:i + per]
            res.append(self.__convert_base(raw_i, base))
        return res

    def read_byte(self, n: int, base: _Base) -> int:
        """nバイト、バイト列を読み、数値として返す"""
        return self.read_bit(n * 8, base)

    def read_variable_length(self, length_header_size: int, base: _Base) -> str | int | bytes | None:
        """可変長ベクトルの長さを読み、本体を読む"""
        vector_len = self.read_byte(length_header_size, "int")
        if vector_len == 0:  # 空ベクトル
            return b""
        vector_bits = vector_len * 8
        self.__check_length(vector_bits)
        res = self.__next_bits(vector_bits)
        return self.__convert_base(res, base, byte_len=vector_len)

    def read_variable_length_per(self, length_header_size: int, per: int, base: _Base) \
            -> list[str | int | bytes] | None:
        raw = self.read_variable_length(length_header_size, "raw")
        res = []
        for i in range(0, len(raw), per):
            byte = raw[i:i + per]
            binary = format(int(byte.hex(), 16), "b")
            res.append(self.__convert_base(binary, base, byte_len=per))
        return res

    def rest_bytes(self) -> bytes:
        return self.__byte_seq[self.__bin_next_pos // 8:]

    def read_rest_bytes(self, base: _Base) -> bytes:
        res = self.__convert_base(self.__bin_seq[self.__bin_next_pos:], base)
        self.__bin_next_pos = self.__bin_length
        return res

    def __check_length(self, n: int):
        if n < 0:
            raise ValueError("0bit以上の数値を指定してください。")
        if self.__bin_length < self.__bin_next_pos + n:
            raise EOFError("これ以上読み進められません。")


class BytesBuilder:
    def __init__(self):
        self.result = b""

    def append(self, data):
        self.result += data

    def to_bytes(self) -> bytes:
        return self.result
