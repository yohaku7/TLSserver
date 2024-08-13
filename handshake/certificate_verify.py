from dataclasses import dataclass
from common import SignatureScheme
from reader import new


@dataclass(frozen=True)
class CertificateVerify(new.TLSObject):
    algorithm: SignatureScheme
    signature: bytes

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            1,
            (2, True)
        ]
