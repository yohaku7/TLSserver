from dataclasses import dataclass

from tls_object import TLSIntEnum
from enum import IntEnum

from reader import new
from .extension_data import ExtensionReply

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
class ECPointFormats(new.TLSObject):
    ec_point_formats: list[ECPointFormat]

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            (1, True, 1),
        ]

    def reply(self) -> ExtensionReply:
        assert ECPointFormat.uncompressed in self.ec_point_formats
        return ExtensionReply(f"ECPointFormat: {ECPointFormat.uncompressed}")
