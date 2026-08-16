from dataclasses import dataclass

from common import SignatureScheme
from reader import new


@dataclass(frozen=True)
class SignatureAlgorithms(new.TLSObject):
    supported_signature_algorithms: list[SignatureScheme]

    def reply(self) -> None:
        assert SignatureScheme.ecdsa_secp256r1_sha256 in self.supported_signature_algorithms

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            (2, True, 2)
        ]


@dataclass(frozen=True)
class SignatureAlgorithmsCert(new.TLSObject):
    supported_signature_algorithms: list[SignatureScheme]

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            (2, True, 2)
        ]
