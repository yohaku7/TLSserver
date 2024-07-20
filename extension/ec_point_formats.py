from dataclasses import dataclass
from reader import Block, ListBlock
from common import ExtensionType, HandshakeType
from .extension_data import ExtensionData
from enum import IntEnum

__all__ = ["ECPointFormats"]

# Reference: RFC8422, https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-9


class ECPointFormat(IntEnum):
    uncompressed = 0
    ansiX962_compressed_prime = 1
    ansiX962_compressed_char2 = 2
    # 255


@dataclass(frozen=True)
class ECPointFormats(ExtensionData):
    ec_point_formats: list[ECPointFormat]

    @property
    def type(self) -> ExtensionType:
        return ExtensionType.ec_point_formats

    @staticmethod
    def parse(data: bytes, handshake_type: HandshakeType):
        return _block.from_bytes(data)

    def unparse(self, handshake_type: HandshakeType) -> bytes:
        return _block.unparse(self.ec_point_formats)


_block = ListBlock(1, 1, "byte", "int", variable=True, each_after_parse=ECPointFormat,
                   after_parse_factory=ECPointFormats)
