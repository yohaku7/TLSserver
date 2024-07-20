from dataclasses import dataclass

from common import SignatureScheme, HandshakeType, ExtensionType
from reader import ListBlock
from .extension_data import ExtensionData


@dataclass(frozen=True)
class SignatureAlgorithms(ExtensionData):
    supported_signature_algorithms: list[SignatureScheme]

    @property
    def type(self) -> ExtensionType:
        return ExtensionType.signature_algorithms

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        ssa = ListBlock(2, 2, "byte", "int", variable=True).from_bytes(byte_seq)
        res = []
        for elem in ssa:
            if elem in [v.value for _, v in SignatureScheme.__members__.items()]:
                res.append(SignatureScheme(elem))
        return SignatureAlgorithms(res)

    def unparse(self, handshake_type: HandshakeType) -> bytes:
        pass


@dataclass(frozen=True)
class SignatureAlgorithmsCert(ExtensionData):
    supported_signature_algorithms: list[SignatureScheme]

    @property
    def type(self) -> ExtensionType:
        return ExtensionType.signature_algorithms_cert

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        ssa = ListBlock(2, 2, "byte", "int", variable=True).from_bytes(byte_seq)
        res = []
        for elem in ssa:
            if elem in [v.value for _, v in SignatureScheme.__members__.items()]:
                res.append(SignatureScheme(elem))
        return SignatureAlgorithms(res)

    def unparse(self, handshake_type: HandshakeType) -> bytes:
        pass
