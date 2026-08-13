from dataclasses import dataclass

from common import HandshakeType
from extension.extension_parser import ExtensionHeader
from reader import new


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
