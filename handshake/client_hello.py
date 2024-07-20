# -*- coding: UTF-8 -*-
# RFC8446 §4.1.2 に基づいたClientHelloとエンコードされた実際のメッセージ（バイト列）。
from dataclasses import dataclass

from common import HandshakeType
from extension import ExtensionParser
from extension.extension_data import ExtensionData
from reader import Block, ListBlock, Blocks
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

    @staticmethod
    def parse(byte_seq: bytes):
        return blocks.from_bytes(byte_seq)

    def unparse(self):
        ext_raw = b""
        for extension in self.extensions:
            ext_raw += ExtensionParser.unparse(extension, HandshakeType.client_hello)
        return blocks.unparse(self.legacy_version,
                              self.random,
                              self.legacy_session_id,
                              self.cipher_suites,
                              self.legacy_compression_methods,
                              ext_raw)


blocks = Blocks([
    Block(2, "byte", "int"),
    Block(32, "byte", "int"),
    Block(1, "byte", "raw", variable=True),
    ListBlock(2, 2, "byte", "int", variable=True, each_after_parse=CipherSuite),
    Block(1, "byte", "int", variable=True),
    Block(2, "byte", "raw", variable=True, after_parse=lambda raw: ExtensionParser.parse(raw, HandshakeType.client_hello)),
], after_parse=ClientHello)
