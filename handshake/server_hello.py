from dataclasses import dataclass

from extension.extension_parser import ExtensionHeader
from .cipher_suite import CipherSuite
from common import HandshakeType
from reader import new

__all__ = ["ServerHello"]


@dataclass(frozen=True)
class ServerHello(new.TLSObject):
    legacy_version: int
    random: int
    legacy_session_id_echo: bytes
    cipher_suite: CipherSuite
    legacy_compression_method: int
    extensions: list[ExtensionHeader]

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            2,
            32,
            (1, True),
            2,
            1,
            (2, True, None, {
                "handshake_type": HandshakeType.server_hello
            })
        ]
