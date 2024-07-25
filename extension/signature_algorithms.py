from dataclasses import dataclass

from common import SignatureScheme, HandshakeType, ExtensionType
from reader import ListBlock, Blocks, EnumListBlock
from .extension_data import ExtensionData


@dataclass(frozen=True)
class SignatureAlgorithms(ExtensionData):
    supported_signature_algorithms: list[SignatureScheme]
    blocks = Blocks([
        EnumListBlock(2, 2, SignatureScheme, variable=True)
    ])


SignatureAlgorithms.blocks.after_parse_factory = SignatureAlgorithms


@dataclass(frozen=True)
class SignatureAlgorithmsCert(ExtensionData):
    supported_signature_algorithms: list[SignatureScheme]
    blocks = Blocks([
        EnumListBlock(2, 2, SignatureScheme, variable=True)
    ])


SignatureAlgorithmsCert.blocks.after_parse_factory = SignatureAlgorithmsCert
