from dataclasses import dataclass

from common import SignatureScheme, HandshakeType
from reader import ListBlock


@dataclass(frozen=True)
class SignatureAlgorithms:
    supported_signature_algorithms: list[SignatureScheme]

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        ssa = ListBlock(2, 2, "byte", "int", variable=True).from_byte(byte_seq)
        res = []
        for elem in ssa:
            if elem in [v.value for _, v in SignatureScheme.__members__.items()]:
                res.append(SignatureScheme(elem))
        return SignatureAlgorithms(res)


@dataclass(frozen=True)
class SignatureAlgorithmsCert:
    supported_signature_algorithms: list[SignatureScheme]

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        ssa = ListBlock(2, 2, "byte", "int", variable=True).from_byte(byte_seq)
        res = []
        for elem in ssa:
            if elem in [v.value for _, v in SignatureScheme.__members__.items()]:
                res.append(SignatureScheme(elem))
        return SignatureAlgorithms(res)
