from dataclasses import dataclass
from extension.extension_data import ExtensionData
from typing import ClassVar
from reader import Blocks, Block
from extension.extension_parser import ExtensionParser
from common import HandshakeType
from .tls_handshake import TLSHandshake


@dataclass(frozen=True)
class EncryptedExtensions(TLSHandshake):
    extensions: list[ExtensionData]
    blocks: ClassVar[Blocks] = Blocks([
        Block(2, "raw", variable=True, after_parse=lambda x: ExtensionParser.parse(x, HandshakeType.encrypted_extensions))
    ])

    def unparse(self):
        ext_raw = ExtensionParser.unparse(self.extensions, HandshakeType.encrypted_extensions)
        return EncryptedExtensions.blocks.unparse(ext_raw)


EncryptedExtensions.blocks.after_parse_factory = EncryptedExtensions
