from dataclasses import dataclass
from tls_object import TLSIntEnum
from enum import IntEnum

from reader import Blocks, EnumListBlock
from .extension_data import ExtensionData, ExtensionReply

__all__ = ["ECPointFormats"]


# Reference: RFC8422, https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-9


class ECPointFormat(TLSIntEnum, IntEnum):
    uncompressed = 0
    ansiX962_compressed_prime = 1
    ansiX962_compressed_char2 = 2

    @classmethod
    def byte_length(cls) -> int:
        return 1


@dataclass(frozen=True)
class ECPointFormats(ExtensionData):
    ec_point_formats: list[ECPointFormat]
    blocks = Blocks([
        EnumListBlock(1, 1, ECPointFormat, variable=True)
    ])

    def reply(self) -> ExtensionReply:
        assert ECPointFormat.uncompressed in self.ec_point_formats
        return ExtensionReply(f"ECPointFormat: {ECPointFormat.uncompressed}")


ECPointFormats.blocks.after_parse_factory = ECPointFormats
