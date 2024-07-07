from dataclasses import dataclass

from common import SignatureScheme
from reader import BytesReader


@dataclass
class SignatureAlgorithms:
    supported_signature_algorithms: list[SignatureScheme]

    @staticmethod
    def parse(byte_seq: bytes):
        br = BytesReader(byte_seq)
        ssa = br.read_variable_length_per(2, 2, "int")
        print(ssa)
        ssa = list(map(SignatureScheme, ssa))
        return SignatureAlgorithms(ssa)


@dataclass
class SignatureAlgorithmsCert:
    supported_signature_algorithms: list[SignatureScheme]

    @staticmethod
    def parse(byte_seq: bytes):
        br = BytesReader(byte_seq)
        ssa = br.read_variable_length_per(2, 2, "int")
        ssa = list(map(SignatureScheme, ssa))
        return SignatureAlgorithms(ssa)
