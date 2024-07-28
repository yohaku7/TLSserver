# -*- coding: UTF-8 -*-
# written by yohaku7
from __future__ import annotations

import enum
from typing import Callable
from dataclasses import dataclass, field, is_dataclass, replace
from Crypto.Util.number import long_to_bytes
from ._types import *
from .ctx import _ContextBase
from tls_object import TLSIntEnum
from .bytes_reader import BytesReader

type _BlockKind = Block | ListBlock | RestBlock | EnumBlock | EnumListBlock | Blocks | BlocksLoop

__all__ = [
    "Block", "ListBlock", "Blocks", "RestBlock", "EnumBlock", "EnumListBlock", "BlocksLoop",
    "_BlockKind", "NewBlocks",
    "from_bytes"
]


@dataclass
class _BlockBase[T]:
    after_parse: Callable[[_DataKind], T] | None = field(default=None, kw_only=True)
    after_parse_factory: type[T] | None = field(default=None, kw_only=True)
    ctx: _ContextBase | None = field(default=None, kw_only=True)

    @staticmethod
    def to_bytes(obj: _DataKind, base: _Base, block_size: int = 0):
        match base:
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
        return res


@dataclass
class Block[T](_BlockBase[T]):
    size: int
    base: _Base
    variable: bool = field(default=False, kw_only=True)

    def parse(self, br: BytesReader) -> _DataKind | T:
        if self.ctx is not None:
            if isinstance(self.ctx, _ContextBase):
                raw = self.ctx.read(br)
        elif self.variable:
            parsed = br.read_variable_length(self.size, self.base)
        else:
            parsed = br.read_byte(self.size, self.base)
        if self.after_parse is not None and self.after_parse_factory is not None:
            raise ValueError("Don't specify both after_parse and after_parse_factory")
        if self.after_parse is not None:
            return self.after_parse(parsed)
        elif self.after_parse_factory is not None:
            return (lambda x: self.after_parse_factory(x))(parsed)
        return parsed

    def unparse(self, obj: _DataKind) -> bytes:
        res: bytes
        block_size = 0 if self.variable else self.size
        res = _BlockBase.to_bytes(obj, self.base, block_size)
        if self.variable:
            length = len(res).to_bytes(self.size)
            res = length + res
        return res

    def from_bytes(self, byte: bytes) -> _DataKind | T:
        br = BytesReader(byte)
        parsed = self.parse(br)
        assert br.rest_length == 0
        return parsed


@dataclass
class ListBlock[TEach, TAll]:
    size: int
    one_size: int
    unit: _Unit
    base: _Base
    variable: bool = field(default=False, kw_only=True)
    each_after_parse: Callable[[_DataKind], TEach] | None = \
        field(default=None, kw_only=True)
    after_parse: Callable[[list[_DataKind]], TAll] | None = \
        field(default=None, kw_only=True)
    after_parse_factory: type | None = field(default=None, kw_only=True)

    def parse(self, br: BytesReader) -> _DataKind | TAll:
        if self.variable:
            assert self.unit == "byte"
            parsed = br.read_variable_length_per(self.size, self.one_size, self.base)
        else:
            # bit_size = self.size if self.unit == "bit" else self.size * 8
            # one_size = self.one_size if self.unit == "bit" else self.one_size * 8
            # parsed = br.read_bit_per(bit_size, one_size, self.base)
            parsed = br.read_byte_per(self.size, self.one_size, self.base)
        if self.each_after_parse is not None:
            parsed = list(map(self.each_after_parse, parsed))
        if self.after_parse is not None and self.after_parse_factory is not None:
            raise ValueError("Don't specify both after_parse and after_parse_factory")
        if self.after_parse is not None:
            return self.after_parse(parsed)
        elif self.after_parse_factory is not None:
            return (lambda x: self.after_parse_factory(x))(parsed)
        return parsed

    def from_bytes(self, byte: bytes) -> _DataKind | TAll:
        br = BytesReader(byte)
        parsed = self.parse(br)
        assert br.rest_length == 0
        return parsed

    def unparse(self, obj_list: list[_DataKind]) -> bytes:
        res = b""
        for obj in obj_list:
            res += _BlockBase.to_bytes(obj, self.base, self.one_size)
        if self.variable:
            length = len(res).to_bytes(self.size)
            res = length + res
        return res


@dataclass
class RestBlock[T]:
    base: _Base
    after_parse: Callable[[_DataKind], T] | None = \
        field(default=None, kw_only=True)

    def parse(self, br: BytesReader) -> _DataKind | T:
        rest_bytes = br.read_rest_bytes(self.base)
        if self.after_parse is None:
            return rest_bytes
        else:
            return self.after_parse(rest_bytes)

    def from_bytes(self, byte: bytes) -> _DataKind | T:
        br = BytesReader(byte)
        parsed = self.parse(br)
        assert br.rest_length == 0
        return parsed

    def unparse(self, obj: _DataKind, size: int = 0) -> bytes:
        return _BlockBase.to_bytes(obj, self.base, size)


@dataclass(frozen=True)
class BlockObj:
    __data: bytes

    def to_bytes(self) -> bytes:
        return self.__data

    def to_int(self) -> int:
        return int.from_bytes(self.__data)

    def to_int_enum(self, enum_type: type[enum.IntEnum]) -> enum.IntEnum:
        for elem in enum_type:
            if elem.value == self.to_int():
                return elem
        raise ValueError("値がEnumに合致しませんでした")

    def split(self, sep_byte: int) -> list[BlockObj]:
        res = []
        i = 0
        while True:
            raw = self.__data[i:i + sep_byte]
            res.append(BlockObj(raw))
            if raw == b"":
                return res


@dataclass
class NewBlocks[T]:
    contexts: list[_ContextBase]

    def parse(self, data: bytes) -> list[BlockObj]:
        br = BytesReader(data)
        res = []
        for ctx in self.contexts:
            res.append(BlockObj(ctx.read(br)))
        return res


@dataclass
class Blocks[T]:
    blocks: list[_BlockKind]
    variable: bool = field(default=False, kw_only=True)
    variable_header_size: int = field(default=None, kw_only=True)
    after_parse: Callable[[*tuple[..., ...]], T] | None = \
        field(default=None, kw_only=True)
    after_parse_factory: type | None = field(default=None, kw_only=True)

    def parse(self, br: BytesReader) -> _DataKind | T:
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

    def from_bytes(self, byte: bytes) -> _DataKind | T:
        br = BytesReader(byte)
        parsed = self.parse(br)
        assert br.rest_length == 0
        return parsed

    def unparse(self, *objs_or_dataclass: object | _DataKind | list[_DataKind]) -> bytes:
        if is_dataclass(objs_or_dataclass[0]):
            # データクラスのフィールドを定義順にunparseさせる
            objs_or_dataclass = list(objs_or_dataclass[0].__dict__.values())
        unparsed = b""
        for block, obj in zip(self.blocks, objs_or_dataclass, strict=True):
            unparsed += block.unparse(obj)
        if self.variable:
            unparsed = long_to_bytes(len(unparsed), self.variable_header_size)
        return unparsed

    def __add__(self, other: _BlockKind):
        return replace(
            self,
            blocks=[*self.blocks, other]
        )

    def __iadd__(self, other: _BlockKind):
        return replace(
            self,
            blocks=[*self.blocks, other]
        )


@dataclass
class BlocksLoop[T]:
    blocks: Blocks[T]

    def parse(self, br: BytesReader) -> list[T]:
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


def from_bytes[T1, T2: _BlockKind, TResult](match: T1,
                                            cases: dict[T1, T2],
                                            byte: bytes,
                                            *, not_match: T2 | None = None) -> _DataKind | TResult:
    if match in cases.keys():
        return cases[match].from_bytes(byte)
    else:
        if not_match is not None:
            return not_match
        raise ValueError("Didn't match")


@dataclass(frozen=True)
class EnumBlock[T: TLSIntEnum]:
    enum: type[T]
    variable: bool = field(default=False, kw_only=True)
    variable_header_size: int | None = field(default=None, kw_only=True)
    unit: _Unit = field(default="byte")

    def parse(self, br: BytesReader) -> int:
        if self.variable:
            assert self.unit == "byte" and self.variable_header_size is not None
            value = br.read_variable_length(self.variable_header_size, "raw")
        else:
            bit_size = self.enum.byte_length() if self.unit == "bit" else self.enum.byte_length() * 8
            value = br.read_bit(bit_size, "raw")
        return self.enum.parse(value)

    def from_bytes(self, data: bytes) -> int:
        br = BytesReader(data)
        return self.parse(br)

    def unparse(self, obj: T) -> bytes:
        data = self.enum.unparse(obj)
        if self.variable:
            assert self.variable_header_size is not None
            data = long_to_bytes(self.enum.byte_length(), self.variable_header_size) + data
        return data


@dataclass(frozen=True)
class EnumListBlock[T: TLSIntEnum]:
    size: int
    one_size: int
    enum: type[T]
    variable: bool = field(default=False, kw_only=True)
    variable_header_size: int | None = field(default=None, kw_only=True)
    unit: _Unit = field(default="byte")

    def parse(self, br: BytesReader) -> list[T]:
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
