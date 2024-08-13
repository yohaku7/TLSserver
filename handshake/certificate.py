from dataclasses import dataclass

from common import HandshakeType
from reader import new
from extension.extension_parser import ExtensionHeader


@dataclass(frozen=True)
class CertificateEntry(new.TLSObject):
    cert_data: bytes  # 3-bytes variable
    extensions: list[ExtensionHeader]

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            (3, True),
            (2, True, None, {
                "handshake_type": HandshakeType.certificate
            })
        ]


@dataclass(frozen=True)
class Certificate(new.TLSObject):
    certificate_request_context: bytes
    certificate_list: CertificateEntry

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            (1, True),
            (3, True),
        ]

    @staticmethod
    def make(cert_data: bytes, extensions: list[ExtensionHeader]):
        entry = CertificateEntry(cert_data, extensions)
        return Certificate(b"", entry)
