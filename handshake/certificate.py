from dataclasses import dataclass

from common import HandshakeType
from reader import Blocks, Block, new
from extension.extension_data import ExtensionData
from extension.extension_parser import ExtensionParser
from typing import ClassVar

from reader.new import BytesConverter, BytesConvertable
from .tls_handshake import TLSHandshake


@dataclass(frozen=True)
class CertificateEntry(new.TLSObject):
    cert_data: bytes  # 3-bytes variable
    extensions: list[ExtensionData]

    @classmethod
    def _get_lengths(cls) -> list[BytesConverter | BytesConvertable]:
        return [
            new.Block(new.Variable(3)),
            new.Block(new.Variable(2), additional_data={
                "handshake_type": HandshakeType.certificate
            })
        ]

    # blocks: ClassVar[Blocks] = Blocks([
    #     Block(3, "raw", variable=True),
    #     Block(2, "raw", variable=True, after_parse=lambda x: ExtensionParser.parse(x, HandshakeType.certificate))
    # ])

    # def unparse(self):
    #     ext_raw = ExtensionParser.unparse(self.extensions, HandshakeType.certificate)
    #     return CertificateEntry.blocks.unparse(
    #         self.cert_data, ext_raw
    #     )


@dataclass(frozen=True)
class Certificate(new.TLSObject):
    certificate_request_context: bytes
    certificate_list: CertificateEntry

    @classmethod
    def _get_lengths(cls) -> list[BytesConverter | BytesConvertable]:
        return [
            new.Block(new.Variable(1)),
            new.Block(new.Variable(3))
        ]

    # blocks: ClassVar[Blocks] = Blocks([
    #     Block(1, "raw", variable=True),
    #     Block(3, "raw", variable=True, after_parse=lambda x: CertificateEntry.blocks.from_bytes(x))
    # ])

    @staticmethod
    def make(cert_data: bytes, extensions: list[ExtensionData]):
        entry = CertificateEntry(cert_data, extensions)
        return Certificate(b"", entry)

    # def unparse(self):
    #     return Certificate.blocks.unparse(
    #         self.certificate_request_context,
    #         self.certificate_list.unparse()
    #     )
