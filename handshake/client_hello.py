# -*- coding: UTF-8 -*-
# RFC8446 §4.1.2 に基づいたClientHelloとエンコードされた実際のメッセージ（バイト列）。
from dataclasses import dataclass
from typing import ClassVar

from common import HandshakeType
from extension import ExtensionParser
from extension.extension_parser import ExtensionHeader
from reader import Block, ListBlock, Blocks
from reader import new
from reader.new import BytesConverter, BytesConvertable
from .cipher_suite import CipherSuite
from .tls_handshake import TLSHandshake

__all__ = ["ClientHello"]


@dataclass(frozen=True)
class ClientHello(new.TLSObject):
    legacy_version: int
    random: int
    legacy_session_id: bytes
    cipher_suites: list[CipherSuite]
    legacy_compression_methods: int
    extensions: list[ExtensionHeader]

    # blocks: ClassVar[Blocks] = Blocks([
    #     Block(2, "int"),
    #     Block(32, "int"),
    #     Block(1, "raw", variable=True),
    #     ListBlock(2, 2, "byte", "int", variable=True, each_after_parse=CipherSuite),
    #     Block(1, "int", variable=True),
    #     Block(2, "raw", variable=True,
    #           after_parse=lambda raw: ExtensionParser.parse(raw, HandshakeType.client_hello)),
    # ])

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
            # new.Length(2),
            # new.Length(32),
            # new.Length(1),
            # new.Block(new.Length(2), split=2),
            # new.Block(new.Length(1)),
            # new.Block(new.Length(2), additional_data={
            #     "handshake_type": HandshakeType.client_hello,
            # })
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
