from abc import ABC, abstractmethod
from dataclasses import dataclass

from .bytes_reader import BytesReader
import inspect


@dataclass(frozen=True)
class _TLSField(ABC):
    @abstractmethod
    def parse(self, br: BytesReader):
        pass

    @abstractmethod
    def from_bytes(self, data: bytes):
        pass

    @abstractmethod
    def unparse(self, obj) -> bytes:
        pass


@dataclass(frozen=True)
class _TLSFieldWithLength(_TLSField, ABC):
    _byte_length: int


@dataclass(frozen=True)
class Raw(_TLSFieldWithLength):
    def parse(self, br: BytesReader):
        return br.read_byte(self._byte_length, "raw")

    def from_bytes(self, data: bytes):
        return data

    def unparse(self, obj: bytes) -> bytes:
        return obj


@dataclass(frozen=True)
class UInt(_TLSFieldWithLength):
    def parse(self, br: BytesReader):
        return br.read_byte(self._byte_length, "int")

    def from_bytes(self, data: bytes):
        return int.from_bytes(data)

    def unparse(self, obj: int) -> bytes:
        return obj.to_bytes(self._byte_length)


UInt8 = UInt(1)
UInt16 = UInt(2)
UInt24 = UInt(3)


@dataclass(frozen=True)
class Variable(_TLSFieldWithLength):
    content: type[_TLSFieldWithLength]

    def parse(self, br: BytesReader):
        length = br.read_byte(self._byte_length, "int")
        if length == 0:
            return b""
        c = self.content(length)
        return c.parse(br)

    def from_bytes(self, data: bytes):
        length = data[:self._byte_length]
        if length == 0:
            return b""
        content = self.content(length)
        return content.from_bytes(data[self._byte_length:])

    def unparse(self, obj) -> bytes:
        content = self.content(self._byte_length)
        content = content.unparse(obj)
        length = len(content).to_bytes(self._byte_length)
        return length + content


class TLSStruct(ABC):
    @classmethod
    def parse(cls, br: BytesReader):
        cls_vars = [i[1] for i in inspect.getmembers_static(cls, lambda x: not callable(x)) if not i[0].startswith("__")]
        res = []
        for cls_var in cls_vars:
            assert isinstance(cls_var, _TLSField)
            parsed = cls_var.parse(br)
            res.append(parsed)
        return res

    @classmethod
    def from_bytes(cls, data: bytes):
        br = BytesReader(data)
        parsed = cls.parse(br)
        assert br.rest_length == 0
        return parsed

    @classmethod
    def unparse(cls, dataclass):
        cls_vars = [i[1] for i in inspect.getmembers_static(cls, lambda x: not callable(x)) if not i[0].startswith("__")]
        values = list(dataclass.__dict__.values())
        res = []
        for cls_var, value in zip(cls_vars, values, strict=True):
            assert isinstance(cls_var, _TLSField)
            unparsed = cls_var.unparse(value)
            res.append(unparsed)
        return res
