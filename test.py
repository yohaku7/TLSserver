from __future__ import annotations

import abc
import types
import typing
from dataclasses import dataclass
from enum import IntEnum
from reader import BytesReader
from Crypto.Util.number import long_to_bytes


class Parsable(metaclass=abc.ABCMeta):
    @classmethod
    @abc.abstractmethod
    def parse(cls, br: BytesReader):
        pass

    @classmethod
    @typing.final
    def from_bytes(cls, data: bytes):
        br = BytesReader(data)
        parsed = cls.parse(br)
        assert br.rest_length == 0
        return parsed


class BytesConverter(Parsable):
    @abc.abstractmethod
    def unparse(self, obj) -> bytes:
        pass


class BytesConvertable(Parsable):
    @abc.abstractmethod
    def unparse(self) -> bytes:
        pass


@dataclass(frozen=True)
class Variable:
    header_byte_length: int


@dataclass(frozen=True)
class Block(BytesConverter):
    byte_length: int | Variable

    def parse(self, br: BytesReader):
        byte_length = _read_length(self.byte_length, br)
        return br.read_byte(byte_length, "raw")

    def unparse(self, obj) -> bytes:
        res = _to_bytes(obj, self.byte_length)
        return _add_length_header(self.byte_length, res) if type(self.byte_length) is Variable else res


@dataclass(frozen=True)
class Split(BytesConverter):
    child: Block
    _one_length: int

    def parse(self, br: BytesReader):
        raw = self.child.parse(br)
        assert len(raw) % self._one_length == 0
        res = []
        for i in range(0, len(raw), self._one_length):
            res.append(raw[i:i + self._one_length])
        return res

    def unparse(self, obj: list):
        # そうでないときは、単純にbytesに変換し結合する
        joined = b''.join([o for o in obj])
        # 分割する対象のBlockの長さがVariableだった場合、長さのヘッダを付ける
        return _add_length_header(self.child.byte_length, joined) if type(self.child.byte_length) is Variable \
            else joined


def _read_length(byte_length: int | Variable, br: BytesReader):
    if isinstance(byte_length, Variable):
        return int.from_bytes(br.read_byte(byte_length.header_byte_length, "raw"))
    return byte_length


def _parse_primitive[T](data: bytes, primitive_type: T) -> T | None:
    if primitive_type is int:
        return int.from_bytes(data)
    elif primitive_type is str:
        return data.decode()
    elif primitive_type is bytes:
        return data
    elif primitive_type is bytearray:
        return bytearray(data)
    elif issubclass(primitive_type, IntEnum):
        return primitive_type(int.from_bytes(data))
    return None


def _to_bytes(obj, byte_length: int | Variable) -> bytes:
    obj_type = type(obj)
    if obj_type is int:
        if type(byte_length) is Variable:
            res = long_to_bytes(obj)
        else:
            res = int.to_bytes(obj, byte_length)
    elif obj_type is str:
        res = obj.encode()
    elif obj_type is bytes:
        res = obj
    elif obj_type is bytearray:
        res = bytes(obj)
    else:
        raise ValueError
    return res


def _get_type_param(__type: types.GenericAlias, ) -> type:
    t_args: tuple[type, ...] = __type.__args__
    assert len(t_args) == 1, ValueError("型パラメータの数は1でなければなりません")
    return t_args[0]


def _add_length_header(variable: Variable, data: bytes) -> bytes:
    return len(data).to_bytes(variable.header_byte_length) + data


@dataclass(frozen=True)
class TLSObject(BytesConvertable, metaclass=abc.ABCMeta):
    @classmethod
    @abc.abstractmethod
    def _get_blocks(cls) -> list[BytesConverter | BytesConvertable]:
        pass

    @classmethod
    @typing.final
    def parse(cls, br: BytesReader):
        # クラスのシグネチャと、分解されたbytesの個数を確認
        parsed_blocks = [block.parse(br) for block in cls._get_blocks()]
        type_hints = typing.get_type_hints(cls)
        assert len(type_hints) == len(parsed_blocks), ValueError("引数の数とBlockの数が違います")

        # クラスのフィールドを埋めていく
        fields = {}
        for f_name, f_type, data in zip(type_hints.keys(), type_hints.values(), parsed_blocks, strict=True):
            parsed = _parse_primitive(data, f_type)
            if parsed is None:
                if isinstance(f_type, types.GenericAlias):
                    t_param = _get_type_param(f_type)
                    fields[f_name] = list(map(lambda x: _parse_primitive(x, t_param), data))
                elif issubclass(f_type, TLSObject):
                    fields[f_name] = data
                else:
                    raise TypeError("パースできない型です。")
            else:
                fields[f_name] = parsed
        return cls(**fields)

    @typing.final
    def unparse(self) -> bytes:
        fields = list(self.__dict__.values())
        unparsed = b''.join([block.unparse(field) for block, field in zip(self._get_blocks(), fields, strict=True)])
        return unparsed


@dataclass(frozen=True)
class _Model(TLSObject):
    a: int
    b: list[bytes]
    c: str

    @classmethod
    def _get_blocks(cls) -> list[BytesConverter | BytesConvertable]:
        return [
            Block(2),
            Split(Block(Variable(1)), 1),
            Block(Variable(1)),
        ]


@dataclass(frozen=True)
class __Model2(TLSObject):
    a: int
    b: _Model

    @classmethod
    def _get_blocks(cls) -> list[BytesConverter | BytesConvertable]:
        return [
            Block(2),
            _Model,
        ]


if __name__ == '__main__':
    print(__Model2.parse(BytesReader(b"\xff\x03" + b'\x00\x05\x03\xff\xff\xff\x05hello')))
    print(__Model2(a=65283, b=_Model(a=5, b=[b'\xff', b'\xff', b'\xff'], c='hello')).unparse())
