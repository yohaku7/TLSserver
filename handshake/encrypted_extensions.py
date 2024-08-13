from dataclasses import dataclass

from reader import new
from extension.extension_parser import ExtensionHeader
from common import HandshakeType


@dataclass(frozen=True)
class EncryptedExtensions(new.TLSObject):
    extensions: list[ExtensionHeader]

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            (2, True, None, {
                "handshake_type": HandshakeType.encrypted_extensions
            })
        ]
