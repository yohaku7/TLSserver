# -*- coding: UTF-8 -*-
# written by yohaku7
from typing import Literal

type Base = Literal["bin", "dec", "hex", "int"]


__all__ = [
    "BytesReader"
]


class BytesReader:
    """バイト列を加工したり、数値を読み取ったりするクラス。"""

    def __init__(self, byte_seq: bytes):
        # self.__byte_seq = byte_seq
        self.__bin_seq: str = format(int(byte_seq.hex(), 16), f"0{len(byte_seq) * 8}b")
        self.__bin_length = len(self.__bin_seq)
        self.__bin_next_pos = 0

    def __next_bits(self, n: int) -> str:
        res = self.__bin_seq[self.__bin_next_pos:self.__bin_next_pos + n]
        self.__bin_next_pos += n
        return res

    def __convert_base(self, binary: str, base: Base):
        if base == "bin":
            return binary
        if base == "dec":
            return str(int(binary, 2))
        if base == "hex":
            return format(int(binary, 2), "x")
        if base == "int":
            return int(binary, 2)

    def read_bit(self, n: int, base: Base) -> int | str:
        """nビット、バイト列を読み、数値として返す"""
        self.__check_length(n)
        res = self.__next_bits(n)
        return self.__convert_base(res, base)

    def read_bits(self, n: int, count: int, base: Base) -> list[str]:
        res = []
        for _ in range(count):
            res.append(self.read_bit(n, base))
        return res

    def read_byte(self, n: int, base: Base) -> int:
        """nバイト、バイト列を読み、数値として返す"""
        return self.read_bit(n * 8, base)

    def read_bytes(self, n: int, count: int, base: Base) -> list[str]:
        return self.read_bits(n * 8, count, base)

    def __check_length(self, n: int):
        if n <= 0:
            raise ValueError("1bit以上読み進めてください。")
        if self.__bin_length < self.__bin_next_pos + n:
            raise EOFError("これ以上読み進められません。")


if __name__ == '__main__':
    b = BytesReader(b"\x48\x3e\x5e\xee\x67\x7c\xa0\x78\x17\xa6\xf5\xec\x86\xdd")
    by = b.read_bytes(1, 6, "dec")
    print(":".join(by))
    by = b.read_bytes(1, 6, "hex")
    print(":".join(by))
    type = b.read_byte(2, "hex")
    print(type)
