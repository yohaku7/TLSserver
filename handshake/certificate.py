from dataclasses import dataclass

from common import HandshakeType
from reader import Blocks, Block
from extension.extension_data import ExtensionData
from extension.extension_parser import ExtensionParser
from typing import ClassVar
from .tls_handshake import TLSHandshake


@dataclass
class CertificateEntry:
    cert_data: bytes  # 3-bytes variable
    extensions: list[ExtensionData]

    blocks: ClassVar[Blocks] = Blocks([
        Block(3, "raw", variable=True),
        Block(2, "raw", variable=True, after_parse=lambda x: ExtensionParser.parse(x, HandshakeType.certificate))
    ])

    def unparse(self):
        ext_raw = ExtensionParser.unparse(self.extensions, HandshakeType.certificate)
        return CertificateEntry.blocks.unparse(
            self.cert_data, ext_raw
        )


@dataclass(frozen=True)
class Certificate(TLSHandshake):
    certificate_request_context: bytes
    certificate_list: CertificateEntry

    blocks: ClassVar[Blocks] = Blocks([
        Block(1, "raw", variable=True),
        Block(3, "raw", variable=True, after_parse=lambda x: CertificateEntry.blocks.from_bytes(x))
    ])

    @staticmethod
    def make(cert_data: bytes, extensions: list[ExtensionData]):
        entry = CertificateEntry(cert_data, extensions)
        return Certificate(b"", entry)

    def unparse(self):
        return Certificate.blocks.unparse(
            self.certificate_request_context,
            self.certificate_list.unparse()
        )
