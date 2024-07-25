# -*- coding: UTF-8 -*-
# written by yohaku7
from __future__ import annotations

from enum import IntEnum
from typing import Literal, Callable
from dataclasses import dataclass, field, is_dataclass, replace
from Crypto.Util.number import long_to_bytes

type Base = Literal["raw", "bin", "dec", "hex", "int", "utf8"]
type Unit = Literal["bit", "byte"]
type BlockKind = Block | ListBlock | RestBlock | EnumBlock | EnumListBlock | Blocks | BlocksLoop
type DataKind = bytes | int | str

__all__ = [
    "BytesReader",
    "Block", "ListBlock", "Blocks", "RestBlock", "EnumBlock", "EnumListBlock", "BlocksLoop",
    "from_bytes"
]


@dataclass
class Block[T]:
    size: int
    unit: Unit
    base: Base
    variable: bool = field(default=False, kw_only=True)
    after_parse: Callable[[DataKind], T] | None = \
        field(default=None, kw_only=True)
    after_parse_factory: type[T] | None = field(default=None, kw_only=True)

    def parse(self, br: "BytesReader") -> DataKind | T:
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

    def unparse(self, obj: DataKind) -> bytes:
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

    def from_bytes(self, byte: bytes) -> DataKind | T:
        br = BytesReader(byte)
        parsed = self.parse(br)
        assert br.rest_length == 0
        return parsed


@dataclass
class ListBlock[TEach, TAll]:
    size: int
    one_size: int
    unit: Unit
    base: Base
    variable: bool = field(default=False, kw_only=True)
    each_after_parse: Callable[[DataKind], TEach] | None = \
        field(default=None, kw_only=True)
    after_parse: Callable[[list[DataKind]], TAll] | None = \
        field(default=None, kw_only=True)
    after_parse_factory: type | None = field(default=None, kw_only=True)

    def parse(self, br: "BytesReader") -> DataKind | TAll:
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

    def from_bytes(self, byte: bytes) -> DataKind | TAll:
        br = BytesReader(byte)
        parsed = self.parse(br)
        assert br.rest_length == 0
        return parsed

    def unparse(self, obj_list: list[DataKind]) -> bytes:
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
class RestBlock[T]:
    base: Base
    after_parse: Callable[[DataKind], T] | None = \
        field(default=None, kw_only=True)

    def parse(self, br: "BytesReader") -> DataKind | T:
        rest_bytes = br.read_rest_bytes(self.base)
        if self.after_parse is None:
            return rest_bytes
        else:
            return self.after_parse(rest_bytes)

    def from_bytes(self, byte: bytes) -> DataKind | T:
        br = BytesReader(byte)
        parsed = self.parse(br)
        assert br.rest_length == 0
        return parsed

    def unparse(self, obj: DataKind, size: int = 0) -> bytes:
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
class Blocks[T]:
    blocks: list[BlockKind]
    variable: bool = field(default=False, kw_only=True)
    variable_header_size: int = field(default=None, kw_only=True)
    after_parse: Callable[[*tuple[..., ...]], T] | None = \
        field(default=None, kw_only=True)
    after_parse_factory: type | None = field(default=None, kw_only=True)

    def parse(self, br: "BytesReader") -> DataKind | T:
        parsed_list = []
        if self.variable:
            assert self.variable_header_size is not None
            proc_br = BytesReader(br.read_variable_length(self.variable_header_size, "raw"))
        else:
            assert self.variable_header_size is None
            proc_br = br
        for block in self.blocks:
            parsed_list.append(block.parse(proc_br))
        if self.after_parse is not None and self.after_parse_factory is not None:
            raise ValueError("Don't specify both after_parse and after_parse_factory")
        if self.after_parse is not None:
            return self.after_parse(*parsed_list)
        if self.after_parse_factory is not None:
            return (lambda *x: self.after_parse_factory(*x))(*parsed_list)
        return parsed_list

    def from_bytes(self, byte: bytes) -> DataKind | T:
        br = BytesReader(byte)
        parsed = self.parse(br)
        assert br.rest_length == 0
        return parsed

    def unparse(self, *objs_or_dataclass: object | DataKind | list[DataKind]) -> bytes:
        if is_dataclass(objs_or_dataclass[0]):
            # データクラスのフィールドを定義順にunparseさせる
            objs_or_dataclass = list(objs_or_dataclass[0].__dict__.values())
        unparsed = b""
        for block, obj in zip(self.blocks, objs_or_dataclass, strict=True):
            unparsed += block.unparse(obj)
        if self.variable:
            unparsed = long_to_bytes(len(unparsed), self.variable_header_size)
        return unparsed

    def __add__(self, other: BlockKind):
        return replace(
            self,
            blocks=[*self.blocks, other]
        )

    def __iadd__(self, other: BlockKind):
        return replace(
            self,
            blocks=[*self.blocks, other]
        )


@dataclass
class BlocksLoop[T]:
    blocks: Blocks[T]

    def parse(self, br: "BytesReader") -> list[T]:
        res = []
        while br.rest_length != 0:
            res.append(br.read(self.blocks))
        return res

    def from_bytes(self, byte: bytes):
        return self.parse(BytesReader(byte))

    def unparse(self, objs: list[T]) -> bytes:
        res = b""
        for obj in objs:
            res += self.blocks.unparse(obj)
        return res


def from_bytes[T1, T2: BlockKind, TResult](match: T1,
                                           cases: dict[T1, T2],
                                           byte: bytes,
                                           *, not_match: T2 | None = None) -> DataKind | TResult:
    if match in cases.keys():
        return cases[match].from_bytes(byte)
    else:
        if not_match is not None:
            return not_match
        raise ValueError("Didn't match")


@dataclass(frozen=True)
class EnumBlock[T: IntEnum]:
    size: int
    enum: type[T]
    variable: bool = field(default=False, kw_only=True)
    unit: Unit = field(default="byte")

    def parse(self, br: "BytesReader") -> T:
        if self.variable:
            assert self.unit == "byte"
            value = br.read_variable_length(self.size, "int")
        else:
            bit_size = self.size if self.unit == "bit" else self.size * 8
            value = br.read_bit(bit_size, "int")
        return self.enum(value)

    def from_bytes(self, data: bytes) -> T:
        br = BytesReader(data)
        return self.parse(br)

    def unparse(self, obj: T) -> bytes:
        return long_to_bytes(obj.value, self.size)


@dataclass(frozen=True)
class EnumListBlock[T: IntEnum]:
    size: int
    one_size: int
    enum: type[T]
    variable: bool = field(default=False, kw_only=True)
    unit: Unit = field(default="byte")

    def parse(self, br: "BytesReader") -> list[T]:
        if self.variable:
            assert self.unit == "byte"
            values = br.read_variable_length_per(self.size, self.one_size, "int")
        else:
            bit_size = self.size if self.unit == "bit" else self.size * 8
            one_size = self.one_size if self.unit == "bit" else self.one_size * 8
            values = br.read_bit_per(bit_size, one_size, "int")
        return list(map(self.enum, values))

    def from_bytes(self, data: bytes) -> list[T]:
        return self.parse(BytesReader(data))

    def unparse(self, obj_list: list[T]) -> bytes:
        res = b""
        for obj in obj_list:
            res += long_to_bytes(obj.value, self.one_size)
        if self.variable:
            length = len(res).to_bytes(self.size)
            res = length + res
        return res


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

    def read(self, block: BlockKind):
        return block.parse(self)

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


class BytesBuilder:
    def __init__(self):
        self.result = b""

    def append(self, data):
        self.result += data

    def to_bytes(self) -> bytes:
        return self.result


def main():
    b = RestBlock("int")
    u = b.unparse(123456789)
    p = b.from_bytes(u)
    print(u.hex(), p)


if __name__ == '__main__':
    main()
