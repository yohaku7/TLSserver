import pytest
from reader import BytesReader, new
from dataclasses import dataclass
from reader.new import BytesConverter, BytesConvertable


@dataclass(frozen=True)
class Class1(new.TLSObject):
    a: int
    b: bytes
    c: str
    d: bytearray

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            2,
            2,
            1,
            1,
        ]


@dataclass(frozen=True)
class Class2(new.TLSObject):
    a: list[int]
    b: list[bytes]

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            (2, False, 1),
            (4, False, 2),
        ]


class TestPrimitiveTypes:
    @pytest.fixture
    def init(self):
        self.br = BytesReader(b"\x00\x01\x02\x03q\x05")

    def test_sole_primitive(self, init):
        expected = Class1(1, b"\x02\x03", "q", bytearray(b"\x05"))
        assert Class1.parse(self.br) == expected

    def test_list_primitive(self, init):
        expected = Class2([0, 1], [b"\x02\x03", b"q\x05"])
        assert Class2.parse(self.br) == expected
