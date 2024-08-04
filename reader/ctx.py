from __future__ import annotations

import typing

from dataclasses import dataclass
from abc import ABC, abstractmethod

if typing.TYPE_CHECKING:
    from .bytes_reader import BytesReader


@dataclass(frozen=True)
class _ContextBase(ABC):
    @property
    def data(self) -> bytes:
        pass

    @abstractmethod
    def read(self, br: BytesReader) -> bytes:
        pass


@dataclass(frozen=True)
class VariableLength(_ContextBase):
    header_byte_length: int

    def read(self, br: BytesReader) -> bytes:
        return br.read_variable_length(self.header_byte_length, "raw")


@dataclass(frozen=True)
class FixedLength(_ContextBase):
    byte_length: int

    def read(self, br: BytesReader) -> bytes:
        return br.read_byte(self.byte_length, "raw")
