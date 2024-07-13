# -*- coding: UTF-8 -*-
# written by yohaku7
from typing import Literal, Callable
from dataclasses import dataclass, field

type Base = Literal["raw", "bin", "dec", "hex", "int"]
type Unit = Literal["bit", "byte"]

__all__ = [
    "BytesReader",
    "Block", "ListBlock", "Blocks"
]


@dataclass
class Block:
    size: int
    unit: Unit
    base: Base
    variable: bool = field(default=False)
    after_parse: Callable[[bytes | str | int], object] | type | None = field(default=None)

    def parse(self, br: "BytesReader"):
        if self.variable:
            assert self.unit == "byte"
            parsed = br.read_variable_length(self.size, self.base)
        else:
            bit_size = self.size if self.unit == "bit" else self.size * 8
            parsed = br.read_bit(bit_size, self.base)
        if self.after_parse is None:
            return parsed
        elif isinstance(self.after_parse, Callable):
            return self.after_parse(parsed)
        elif isinstance(self.after_parse, type):
            return (lambda x: self.after_parse(x))(parsed)

    def from_byte(self, byte: bytes):
        br = BytesReader(byte)
        return self.parse(br)


@dataclass
class ListBlock:
    size: int
    one_size: int
    unit: Unit
    base: Base
    variable: bool = field(default=False)
    each_after_parse: Callable[[bytes | str | int], object] | type | None = field(default=None)
    after_parse: Callable[[list[bytes | str | int]], object] | None = field(default=None)

    def parse(self, br: "BytesReader"):
        if self.variable:
            assert self.unit == "byte"
            parsed = br.read_variable_length_per(self.size, self.one_size, self.base)
        else:
            bit_size = self.size if self.unit == "bit" else self.size * 8
            one_size = self.one_size if self.unit == "bit" else self.one_size * 8
            parsed = br.read_bit_per(bit_size, self.one_size, self.base)
        if self.each_after_parse is not None:
            parsed = list(map(self.each_after_parse, parsed))
        if self.after_parse is not None:
            if isinstance(self.after_parse, Callable):
                return self.after_parse(parsed)
            else:
                raise ValueError("after_parseにはCallableを指定してください。")
        else:
            return parsed

    def from_byte(self, byte: bytes):
        br = BytesReader(byte)
        return self.parse(br)


@dataclass
class Blocks:
    blocks: list[Block | ListBlock]
    after_parse: Callable[[*tuple[..., ...]], object] | None = field(default=None)

    def parse(self, br: "BytesReader"):
        parsed_list = []
        for block in self.blocks:
            parsed_list.append(block.parse(br))
        assert br.rest_length == 0
        if self.after_parse is None:
            return parsed_list
        else:
            return self.after_parse(*parsed_list)

    def from_byte(self, byte: bytes):
        br = BytesReader(byte)
        return self.parse(br)


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

    def parse_blocks(self, blocks: list[Block | ListBlock]):
        res = []
        for block in blocks:
            res.append(block.parse(self))
        return res

    def __next_bits(self, n: int) -> str:
        res = self.__bin_seq[self.__bin_next_pos:self.__bin_next_pos + n]
        self.__bin_next_pos += n
        return res

    def __convert_base(self, binary: str, base: Base):
        if base == "raw":
            return int(binary, 2).to_bytes(byteorder="big")
        if base == "bin":
            return binary
        if base == "dec":
            return str(int(binary, 2))
        if base == "hex":
            return format(int(binary, 2), "x")
        if base == "int":
            return int(binary, 2)

    def read_bit(self, n: int, base: Base) -> int | str | bytes:
        """nビット、バイト列を読み、数値として返す"""
        self.__check_length(n)
        res = self.__next_bits(n)
        return self.__convert_base(res, base)

    def read_bits(self, n: int, count: int, base: Base) -> list[str | int | bytes]:
        res = []
        for _ in range(count):
            res.append(self.read_bit(n, base))
        return res

    def read_bit_per(self, n: int, per: int, base: Base) -> list[str | int | bytes]:
        raw = self.read_bit(n, "raw")
        res = []
        for i in range(0, len(raw), per):
            byte = raw[i:i + per]
            binary = format(int(byte.hex(), 16), "b")
            res.append(self.__convert_base(binary, base))
        return res


    def read_byte(self, n: int, base: Base) -> int:
        """nバイト、バイト列を読み、数値として返す"""
        return self.read_bit(n * 8, base)

    def read_bytes(self, n: int, count: int, base: Base) -> list[str | int | bytes]:
        return self.read_bits(n * 8, count, base)

    def read_variable_length(self, length_header_size: int, base: Base) -> str | int | bytes | None:
        """可変長ベクトルの長さを読み、本体を読む"""
        vector_len = self.read_byte(length_header_size, "int")
        if vector_len == 0:  # 空ベクトル
            print("************** 空ベクトルはb\"\"を返します。")
            return b""
        vector_bits = vector_len * 8
        self.__check_length(vector_bits)
        res = self.__next_bits(vector_bits)
        # 巨大な整数のときは、ここで迂回させる（オーバーフロー対策）
        # TODO: 全関数に対してのint#to_bytesのlength引数の適用（"raw"設定時）
        if base == "raw":
            return int(res, 2).to_bytes(length=vector_len, byteorder="big")
        else:
            return self.__convert_base(res, base)

    def read_variable_length_per(self, length_header_size: int, per: int, base: Base) -> list[str | int | bytes] | None:
        raw = self.read_variable_length(length_header_size, "raw")
        res = []
        for i in range(0, len(raw), per):
            byte = raw[i:i + per]
            binary = format(int(byte.hex(), 16), "b")
            res.append(self.__convert_base(binary, base))
        return res

    def rest_bytes(self) -> bytes:
        return self.__byte_seq[self.__bin_next_pos // 8:]

    def __check_length(self, n: int):
        if n < 0:
            raise ValueError("0bit以上の数値を指定してください。")
        if self.__bin_length < self.__bin_next_pos + n:
            raise EOFError("これ以上読み進められません。")


if __name__ == '__main__':
    b = BytesReader(b"\x00\x02\x03\x04")
    by = b.read_variable_length(1, "int")
    print(by)
    print(b.rest_bytes())
