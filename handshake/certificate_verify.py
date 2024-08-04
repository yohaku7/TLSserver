from typing import ClassVar
from dataclasses import dataclass
from common import SignatureScheme
from reader import Blocks, Block, EnumBlock
from .tls_handshake import TLSHandshake


@dataclass(frozen=True)
class CertificateVerify(TLSHandshake):
    algorithm: SignatureScheme
    signature: bytes

    blocks: ClassVar[Blocks] = Blocks([
        EnumBlock(SignatureScheme),
        Block(2, "raw", variable=True)
    ])

    def unparse(self):
        return CertificateVerify.blocks.unparse(self)
