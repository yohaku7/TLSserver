# -*- coding: UTF-8 -*-
# RFC8446 §4.1.2 に基づいたClientHelloとエンコードされた実際のメッセージ（バイト列）。
from dataclasses import dataclass, field

from .cipher_suite import CipherSuite
from reader import BytesBuilder, Block, ListBlock, Blocks
from extension import Extension
from common import HandshakeType


@dataclass(frozen=True)
class ClientHello:
    random: int
    legacy_session_id: bytes
    cipher_suites: list[CipherSuite]
    extensions: list[Extension]
    legacy_version: int = field(default=0x0303)
    legacy_compression_methods: int = field(default=0)

    @staticmethod
    def parse(byte_seq: bytes):
        client_hello = Blocks([
            Block(2, "byte", "int"),
            Block(32, "byte", "int"),
            Block(1, "byte", "raw", variable=True),
            ListBlock(2, 2, "byte", "int", variable=True, each_after_parse=CipherSuite),
            Block(1, "byte", "int", variable=True),
            Block(2, "byte", "raw", variable=True, after_parse=lambda raw: Extension.parse(raw, HandshakeType.client_hello)),
        ], after_parse=lambda lv, r, lsi, cs, lcm, ext: ClientHello(
            legacy_version=lv, random=r,
            legacy_session_id=lsi, cipher_suites=cs,
            legacy_compression_methods=lcm, extensions=ext
        )).from_byte(byte_seq)
        return client_hello

    def unparse(self):
        bb = BytesBuilder()
        bb.append_int(self.legacy_version, 2)
        bb.append_int(self.random, 32)
        bb.append_variable_length(1, self.legacy_session_id.to_bytes(len(hex(self.legacy_session_id)[2:])))
        bb.append_variable_length(2, self.cipher_suites)
