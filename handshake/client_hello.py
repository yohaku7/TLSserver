# -*- coding: UTF-8 -*-
# RFC8446 §4.1.2 に基づいたClientHelloとエンコードされた実際のメッセージ（バイト列）。
from dataclasses import dataclass
from typing import ClassVar

from common import HandshakeType
from extension import ExtensionParser
from extension.extension_data import ExtensionData
from reader import Block, ListBlock, Blocks, ctx, NewBlocks
from .cipher_suite import CipherSuite

__all__ = ["ClientHello"]


@dataclass(frozen=True)
class ClientHello:
    legacy_version: int
    random: int
    legacy_session_id: bytes
    cipher_suites: list[CipherSuite]
    legacy_compression_methods: int
    extensions: list[ExtensionData]

    blocks: ClassVar[Blocks] = Blocks([
        Block(2, "int"),
        Block(32, "int"),
        Block(1, "raw", variable=True),
        ListBlock(2, 2, "byte", "int", variable=True, each_after_parse=CipherSuite),
        Block(1, "int", variable=True),
        Block(2, "raw", variable=True,
              after_parse=lambda raw: ExtensionParser.parse(raw, HandshakeType.client_hello)),
    ])

    def unparse(self):
        ext_raw = ExtensionParser.unparse(self.extensions, HandshakeType.client_hello)
        return ClientHello.blocks.unparse(self.legacy_version,
                                          self.random,
                                          self.legacy_session_id,
                                          self.cipher_suites,
                                          self.legacy_compression_methods,
                                          ext_raw)


ClientHello.blocks.after_parse_factory = ClientHello
