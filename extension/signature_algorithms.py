from dataclasses import dataclass

from common import SignatureScheme, HandshakeType
from reader import BytesReader


@dataclass
class SignatureAlgorithms:
    supported_signature_algorithms: list[SignatureScheme]

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        br = BytesReader(byte_seq)
        ssa = br.read_variable_length_per(2, 2, "int")
        res = []
        for elem in ssa:
            if elem in [v.value for _, v in SignatureScheme.__members__.items()]:
                res.append(SignatureScheme(elem))
        return SignatureAlgorithms(res)


@dataclass
class SignatureAlgorithmsCert:
    supported_signature_algorithms: list[SignatureScheme]

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        br = BytesReader(byte_seq)
        ssa = br.read_variable_length_per(2, 2, "int")
        res = []
        for elem in ssa:
            if elem in [v.value for _, v in SignatureScheme.__members__.items()]:
                res.append(SignatureScheme(elem))
        return SignatureAlgorithms(res)
