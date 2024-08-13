# -*- coding: UTF-8 -*-
# RFC8446 §4.1.2 に基づいたClientHelloとエンコードされた実際のメッセージ（バイト列）。
from dataclasses import dataclass

from common import HandshakeType
from extension.extension_parser import ExtensionHeader
from reader import new
from .cipher_suite import CipherSuite

__all__ = ["ClientHello"]


@dataclass(frozen=True)
class ClientHello(new.TLSObject):
    legacy_version: int
    random: int
    legacy_session_id: bytes
    cipher_suites: list[CipherSuite]
    legacy_compression_methods: int
    extensions: list[ExtensionHeader]

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            2,
            32,
            (1, True),
            (2, True, 2),
            (1, True),
            (2, True, None, {
                "handshake_type": HandshakeType.client_hello,
            })
        ]

    # def unparse(self):
    #     ext_raw = ExtensionParser.unparse(self.extensions, HandshakeType.client_hello)
    #     return ClientHello.blocks.unparse(self.legacy_version,
    #                                       self.random,
    #                                       self.legacy_session_id,
    #                                       self.cipher_suites,
    #                                       self.legacy_compression_methods,
    #                                       ext_raw)


# ClientHello.blocks.after_parse_factory = ClientHello
