from dataclasses import dataclass

from common import SignatureScheme
from reader import new
from reader.new import BytesConverter, BytesConvertable


@dataclass(frozen=True)
class SignatureAlgorithms(new.TLSObject):
    supported_signature_algorithms: list[SignatureScheme]

    @classmethod
    def _get_lengths(cls) -> list[BytesConverter | BytesConvertable]:
        return [
            new.Block(new.Variable(2), split=2),
        ]


@dataclass(frozen=True)
class SignatureAlgorithmsCert(new.TLSObject):
    supported_signature_algorithms: list[SignatureScheme]

    @classmethod
    def _get_lengths(cls) -> list[BytesConverter | BytesConvertable]:
        return [
            new.Block(new.Variable(2), split=2),
        ]
