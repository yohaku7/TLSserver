# -*- coding: UTF-8 -*-
# written by yohaku7
from __future__ import annotations

from typing import Literal, Callable, ClassVar
from dataclasses import dataclass, field, replace
from Crypto.Util.number import long_to_bytes

from common import ExtensionType, HandshakeType

type Base = Literal["raw", "bin", "dec", "hex", "int", "utf8"]
type Unit = Literal["bit", "byte"]

__all__ = [
    "BytesReader",
    "Block", "ListBlock", "Blocks", "RestBlock",
    "ExtensionBlock"
]


@dataclass
class Block:
    size: int
    unit: Unit
    base: Base
    variable: bool = field(default=False, kw_only=True)
    after_parse: Callable[[bytes | str | int], object] | None = \
        field(default=None, kw_only=True)
    after_parse_factory: type | None = field(default=None, kw_only=True)

    def parse(self, br: "BytesReader"):
        if self.variable:
            assert self.unit == "byte"
            parsed = br.read_variable_length(self.size, self.base)
        else:
            bit_size = self.size if self.unit == "bit" else self.size * 8
            parsed = br.read_bit(bit_size, self.base)
        if self.after_parse is not None and self.after_parse_factory is not None:
            raise ValueError("Don't specify both after_parse and after_parse_factory")
        if self.after_parse is not None:
            return self.after_parse(parsed)
        elif self.after_parse_factory is not None:
            return (lambda x: self.after_parse_factory(x))(parsed)
        return parsed

    def unparse(self, obj: bytes | str | int) -> bytes:
        res: bytes
        block_size = 0 if self.variable else self.size
        match self.base:
            case "raw":
                res = obj
            case "utf8":
                res = obj.encode("utf-8")
            case "int":
                res = long_to_bytes(obj, block_size)
            case "bin":
                res = long_to_bytes(int(obj, 2), block_size)
            case "dec":
                res = long_to_bytes(int(obj), block_size)
            case "hex":
                res = long_to_bytes(int(obj, 16), block_size)
            case _:
                raise ValueError("self.baseが不正です")
        if self.variable:
            length = len(res).to_bytes(self.size)
            res = length + res
        return res

    def from_bytes(self, byte: bytes):
        br = BytesReader(byte)
        parsed = self.parse(br)
        assert br.rest_length == 0
        return parsed


@dataclass
class ListBlock:
    size: int
    one_size: int
    unit: Unit
    base: Base
    variable: bool = field(default=False, kw_only=True)
    each_after_parse: Callable[[bytes | str | int], object] | None = \
        field(default=None, kw_only=True)
    after_parse: Callable[[list[bytes | str | int]], object] | None = \
        field(default=None, kw_only=True)
    after_parse_factory: type | None = field(default=None, kw_only=True)

    def parse(self, br: "BytesReader"):
        if self.variable:
            assert self.unit == "byte"
            parsed = br.read_variable_length_per(self.size, self.one_size, self.base)
        else:
            bit_size = self.size if self.unit == "bit" else self.size * 8
            one_size = self.one_size if self.unit == "bit" else self.one_size * 8
            parsed = br.read_bit_per(bit_size, one_size, self.base)
        if self.each_after_parse is not None:
            parsed = list(map(self.each_after_parse, parsed))
        if self.after_parse is not None and self.after_parse_factory is not None:
            raise ValueError("Don't specify both after_parse and after_parse_factory")
        if self.after_parse is not None:
            return self.after_parse(parsed)
        elif self.after_parse_factory is not None:
            return (lambda x: self.after_parse_factory(x))(parsed)
        return parsed

    def from_bytes(self, byte: bytes):
        br = BytesReader(byte)
        parsed = self.parse(br)
        assert br.rest_length == 0
        return parsed

    def unparse(self, obj_list: list[bytes | str | int]):
        res = b""
        for obj in obj_list:
            match self.base:
                case "raw":
                    res += obj
                case "utf8":
                    res += obj.encode("utf-8")
                case "int":
                    res += long_to_bytes(obj, self.one_size)
                case "bin":
                    res += long_to_bytes(int(obj, 2), self.one_size)
                case "dec":
                    res += long_to_bytes(int(obj), self.one_size)
                case "hex":
                    res += long_to_bytes(int(obj, 16), self.one_size)
                case _:
                    raise ValueError("self.baseが不正です")
        if self.variable:
            length = len(res).to_bytes(self.size)
            res = length + res
        return res


@dataclass
class RestBlock:
    base: Base
    after_parse: Callable[[bytes | str | int], object] | None = \
        field(default=None, kw_only=True)

    def parse(self, br: "BytesReader"):
        rest_bytes = br.read_rest_bytes(self.base)
        if self.after_parse is None:
            return rest_bytes
        else:
            return self.after_parse(rest_bytes)

    def from_bytes(self, byte: bytes):
        br = BytesReader(byte)
        parsed = self.parse(br)
        assert br.rest_length == 0
        return parsed

    def unparse(self, obj: bytes | str | int, size: int = 0):
        res: bytes
        match self.base:
            case "raw":
                res = obj
            case "utf8":
                res = obj.encode("utf-8")
            case "int":
                res = long_to_bytes(obj, size)
            case "bin":
                res = long_to_bytes(int(obj, 2), size)
            case "dec":
                res = long_to_bytes(int(obj), size)
            case "hex":
                res = long_to_bytes(int(obj, 16), size)
            case _:
                raise ValueError("self.baseが不正です")
        return res


@dataclass
class ExtensionBlock:
    __type_block: ClassVar[Block] = Block(2, "byte", "int", after_parse=ExtensionType)

    type: ExtensionType
    data_blocks: Blocks

    def parse(self, byte: bytes, handshake_type: HandshakeType | None = None):
        br = BytesReader(byte)
        type_val = ExtensionBlock.__type_block.parse(br)
        assert type_val == self.type
        data = self.data_blocks.parse(br)
        return data

    def from_bytes(self, byte: bytes, handshake_type: HandshakeType | None = None):
        br = BytesReader(byte)
        return self.parse(br)

    def unparse(self, *objs: list[bytes | str | int], handshake_type: HandshakeType | None = None):
        type_raw = ExtensionBlock.__type_block.unparse(self.type)
        data_raw = self.data_blocks.unparse(*objs)
        return type_raw + data_raw


@dataclass
class Blocks:
    blocks: list[Block | ListBlock | Blocks]
    variable: bool = field(default=False, kw_only=True)
    after_parse: Callable[[*tuple[..., ...]], object] | None = \
        field(default=None, kw_only=True)
    after_parse_factory: type | None = field(default=None, kw_only=True)

    def parse(self, br: "BytesReader"):
        parsed_list = []
        for block in self.blocks:
            parsed_list.append(block.parse(br))
        if self.after_parse is not None and self.after_parse_factory is not None:
            raise ValueError("Don't specify both after_parse and after_parse_factory")
        if self.after_parse is not None:
            return self.after_parse(*parsed_list)
        if self.after_parse_factory is not None:
            return (lambda *x: self.after_parse_factory(*x))(*parsed_list)
        return parsed_list

    def from_bytes(self, byte: bytes):
        br = BytesReader(byte)
        parsed = self.parse(br)
        assert br.rest_length == 0
        return parsed

    def unparse(self, *objs: bytes | str | int | list[bytes | str | int]) -> bytes:
        unparsed = b""
        for block, obj in zip(self.blocks, objs, strict=True):
            unparsed += block.unparse(obj)
        return unparsed


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

    def __convert_base(self, binary: str, base: Base, *, byte_len: int | None = None):
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

    def read_bit(self, n: int, base: Base) -> int | str | bytes:
        """nビット、バイト列を読み、数値として返す"""
        self.__check_length(n)
        res = self.__next_bits(n)
        return self.__convert_base(res, base)

    def read_bit_per(self, n: int, per: int, base: Base) -> list[str | int | bytes]:
        raw = self.read_bit(n, "bin")
        res = []
        for i in range(0, len(raw), per):
            binary = raw[i:i + per]
            res.append(self.__convert_base(binary, base))
        return res

    def read_byte(self, n: int, base: Base) -> int:
        """nバイト、バイト列を読み、数値として返す"""
        return self.read_bit(n * 8, base)

    def read_variable_length(self, length_header_size: int, base: Base) -> str | int | bytes | None:
        """可変長ベクトルの長さを読み、本体を読む"""
        vector_len = self.read_byte(length_header_size, "int")
        if vector_len == 0:  # 空ベクトル
            return b""
        vector_bits = vector_len * 8
        self.__check_length(vector_bits)
        res = self.__next_bits(vector_bits)
        return self.__convert_base(res, base, byte_len=vector_len)

    def read_variable_length_per(self, length_header_size: int, per: int, base: Base) \
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

    def read_rest_bytes(self, base: Base) -> bytes:
        res = self.__convert_base(self.__bin_seq[self.__bin_next_pos:], base)
        self.__bin_next_pos = self.__bin_length
        return res

    def __check_length(self, n: int):
        if n < 0:
            raise ValueError("0bit以上の数値を指定してください。")
        if self.__bin_length < self.__bin_next_pos + n:
            raise EOFError("これ以上読み進められません。")


def main():
    b = RestBlock("int")
    u = b.unparse(123456789)
    p = b.from_bytes(u)
    print(u.hex(), p)


if __name__ == '__main__':
    main()
