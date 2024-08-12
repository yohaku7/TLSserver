from __future__ import annotations

import abc
import dataclasses
import types
import typing
from dataclasses import dataclass
from enum import IntEnum
from Crypto.Util.number import long_to_bytes
from reader import BytesReader

__all__ = [
    "BytesConvertable", "BytesConverter",
    "Variable", "Block", "TLSObject"
]

_PRIMITIVE_TYPES = (
    int,
    str,
    bytes,
    bytearray,
)
_COLLECTIONS = (
    list,
)


@dataclass(frozen=True)
class Length:
    __in_byte: int
    variable: bool = False
    split: int | None = None

    def read(self, br: BytesReader) -> bytes:
        raw: bytes
        if not self.variable:
            raw = br.read_byte(self.__in_byte, "raw")
        else:
            length = br.read_byte(self.__in_byte, "int")
            raw = br.read_byte(length, "raw")
        return raw if self.split is None else _split_bytes(raw, self.split)


def _split_bytes(raw: bytes, split: int):
    res = []
    for i in range(0, len(raw), split):
        res.append(raw[i:i + split])
    return res



class Parsable(metaclass=abc.ABCMeta):
    @classmethod
    @abc.abstractmethod
    def parse(cls, br: BytesReader, **additional_data):
        pass

    @classmethod
    @typing.final
    def from_bytes(cls, data: bytes, **additional_data):
        br = BytesReader(data)
        parsed = cls.parse(br, **additional_data)
        assert br.rest_length == 0
        return parsed


class BytesConverter:
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
    byte_length: int | Length
    additional_data: dict = dataclasses.field(default_factory=dict, kw_only=True)
    split: int | None = dataclasses.field(default=None, kw_only=True)

    def parse(self, br: BytesReader):
        byte_length = _read_length(self.byte_length, br)
        raw = br.read_byte(byte_length, "raw")
        if self.split is None:
            return raw
        assert len(raw) % self.split == 0
        res = []
        for i in range(0, len(raw), self.split):
            res.append(raw[i:i + self.split])
        return res

    def unparse(self, obj) -> bytes:
        if isinstance(obj, list):
            res = b""
            for o in obj:
                res += _to_bytes(o, self.split)
        else:
            res = _to_bytes(obj, self.byte_length)
        return _add_length_header(self.byte_length, res) if type(self.byte_length) is Variable else res


# @dataclass(frozen=True)
# class Split(BytesConverter):
#     child: Block
#     _one_length: int
#
#     def parse(self, br: BytesReader):
#         raw = self.child.parse(br)
#         assert len(raw) % self._one_length == 0
#         res = []
#         for i in range(0, len(raw), self._one_length):
#             res.append(raw[i:i + self._one_length])
#         return res
#
#     def unparse(self, obj: list):
#         # bytesに変換し結合する
#         joined = b''.join([_to_bytes(o, self._one_length) for o in obj])
#         # 分割する対象のBlockの長さがVariableだった場合、長さのヘッダを付ける
#         return _add_length_header(self.child.byte_length, joined) if type(self.child.byte_length) is Variable \
#             else joined


# @dataclass(frozen=True)
# class Branch(metaclass=abc.ABCMeta):
#     @classmethod
#     @abc.abstractmethod
#     def parse(cls, br: BytesReader, **additional_data):
#         pass
#
#     @classmethod
#     @typing.final
#     def from_bytes(cls, data: bytes, **additional_data):
#         br = BytesReader(data)
#         parsed = cls.parse(br, **additional_data)
#         assert br.rest_length == 0
#         return parsed


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
    raise ValueError(f"パースできません。 type: {primitive_type}")


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
    elif issubclass(obj_type, IntEnum):
        if type(byte_length) is Variable:
            res = long_to_bytes(obj.value)
        else:
            res = int.to_bytes(obj.value, byte_length)
    elif issubclass(obj_type, TLSObject):
        res = obj.unparse()
    else:
        raise ValueError(f"{obj_type}, obj: {obj}")
    return res


def _get_types(__type: types.GenericAlias) -> (type, type):
    t_args: tuple[type, ...] = __type.__args__
    assert len(t_args) == 1, ValueError("型パラメータの数は1でなければなりません")
    return __type.__origin__, t_args[0]


def _add_length_header(variable: Variable, data: bytes) -> bytes:
    return len(data).to_bytes(variable.header_byte_length) + data


def _parse(data, __type, block):
    if isinstance(__type, type):  # primitive type or BytesConvertable
        if isinstance(__type, TLSObject):
            return __type.from_bytes(data)
        return _parse_primitive(data, __type)
    if isinstance(__type, types.GenericAlias):  # GenericAlias (e.g. list[int])
        t_origin, t_param = _get_types(__type)
        return list(map(lambda x: _parse(x, t_param, block), data))
    return _parse_primitive(data, __type)


@dataclass(frozen=True)
class TLSObject(BytesConvertable):
    @classmethod
    @abc.abstractmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        pass

    @classmethod
    @typing.final
    def parse(cls, br: BytesReader, **additional_data):
        # クラスのシグネチャと、分解されたbytesの個数を確認
        type_hints = typing.get_type_hints(cls)
        lengths: list[int | None] = cls._get_lengths()
        assert len(type_hints) == len(lengths), ValueError("引数の数とBlockの数が違います")

        def __parse(length: int, variable: bool, split: int | None, type_annotation: type,
                    **add_data):
            if variable:
                raw = br.read_byte(br.read_byte(length, "int"), "raw")
            else:
                raw = br.read_byte(length, "raw")
            raw = raw if split is None else _split_bytes(raw, split)

            if type_annotation in _PRIMITIVE_TYPES or issubclass(type(type_annotation), IntEnum):
                return _parse_primitive(raw, type_annotation)
            elif isinstance(type_annotation, types.GenericAlias) and type(raw) is bytes:
                t_origin, t_param = _get_types(type_annotation)
                assert issubclass(t_origin, list)
                assert issubclass(t_param, TLSObject)
                list_br = BytesReader(raw)
                res = []
                while list_br.rest_length != 0:
                    res.append(t_param.parse(list_br, **add_data))
                return res
            elif type(raw) is list:
                assert isinstance(type_annotation, types.GenericAlias)
                t_origin, t_param = _get_types(type_annotation)
                assert t_origin is list
                if isinstance(t_param, TLSObject):
                    return list(map(lambda x: t_param.from_bytes(x, **add_data), raw))
                else:
                    return list(map(lambda x: _parse_primitive(x, t_param), raw))
            else:
                print(f"len: {length}, variable: {variable}, split: {split}, t_anno: {type_annotation}")
                raise TypeError(f"raw: {raw} type: {type(raw)}")

        # クラスのフィールドを埋めていく
        fields = {}
        for f_name, f_type, length in zip(type_hints.keys(), type_hints.values(),
                                         lengths, strict=True):
            print(f"{f_name}を読んでいるよ！")
            if length is None:
                assert issubclass(f_type, TLSObject)
                fields[f_name] = f_type.parse(br, **additional_data)
            elif isinstance(length, int):
                print(length)
                fields[f_name] = __parse(length, False, None, f_type)
            elif isinstance(length, tuple):
                if len(length) == 1:
                    length = length[0]
                    fields[f_name] = __parse(length, False, None, f_type)
                elif len(length) == 2:
                    length, variable = length[0], length[1]
                    fields[f_name] = __parse(length, variable, None, f_type)
                elif len(length) == 3:
                    length, variable, split = length[0], length[1], length[2]
                    fields[f_name] = __parse(length, variable, split, f_type)
                elif len(length) == 4:
                    length, variable, split, add_data = length[0], length[1], length[2], length[3]
                    fields[f_name] = __parse(length, variable, split, f_type, **add_data)
                else:
                    raise ValueError("タプルの長さは4以下でなければなりません。")
            else:
                raise TypeError(f"name: {f_name}, type: {f_type}")
        return cls(**fields)._after_parse(**additional_data)


        # for f_name, f_type, block in zip(type_hints.keys(), type_hints.values(),
        #                                  lengths, strict=True):
        #     if issubclass(block.__class__, TLSObject):
        #         fields[f_name] = block.parse(br)
        #         continue
        #
        #     if issubclass(block.__class__, TLSObject):
        #         fields[f_name] = block.parse(br)
        #     elif isinstance(block, Length):
        #
        #     elif f_type in _PRIMITIVE_TYPES:
        #         fields[f_name] = _parse_primitive(block.parse(br), f_type)
        #     elif issubclass(f_type.__class__, TLSObject):
        #         fields[f_name] = f_type.parse(br, **block.additional_data)
        #     elif issubclass(f_type, IntEnum):
        #         fields[f_name] = f_type(int.from_bytes(block.parse(br)))
        #     elif isinstance(f_type, types.GenericAlias):
        #         t_origin, t_param = _get_types(f_type)
        #         if t_origin not in _COLLECTIONS:
        #             raise TypeError(f"コレクション '{t_origin}' はパースできません")
        #         raw_list = block.parse(br)
        #         if t_param in _PRIMITIVE_TYPES:
        #             fields[f_name] = t_origin(map(lambda x: _parse_primitive(x, t_param), raw_list))
        #         elif issubclass(t_param, TLSObject):
        #             list_br = BytesReader(raw_list)
        #             res = []
        #             while list_br.rest_length != 0:
        #                 res.append(t_param.parse(list_br, **block.additional_data))
        #             fields[f_name] = res
        #         elif issubclass(t_param, IntEnum):
        #             fields[f_name] = t_origin(map(lambda x: t_param(int.from_bytes(x)), raw_list))
        #         else:
        #             raise TypeError(f"型 {t_param} はパースできません")
        # return cls(**fields)._after_parse(**additional_data)

    def _after_parse(self, **additional_data):
        return self

    @typing.final
    def unparse(self) -> bytes:
        blocks: list[Parsable] = self._get_lengths()
        values = list(self.__dict__.values())
        assert len(blocks) == len(values)
        unparsed = b""
        for value, block in zip(values, blocks, strict=True):
            if isinstance(block, TLSObject):
                unparsed += block.unparse()
            else:
                unparsed += block.unparse(value)
        # unparsed = b''.join([block.unparse(field) for block, field in zip(self._get_blocks(), values, strict=True)])
        return unparsed
