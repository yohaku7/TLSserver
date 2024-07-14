from dataclasses import dataclass, field
from typing import ClassVar
from Crypto.Util.number import getRandomNBitInteger

from .cipher_suite import CipherSuite
from .client_hello import ClientHello

from extension.extension import Extension
from extension.supported_versions import SupportedVersions
from common import ExtensionType, HandshakeType
from reader import BytesBuilder, Blocks, Block

__all__ = ["ServerHello"]


@dataclass(frozen=True)
class ServerHello:
    random: int
    legacy_session_id_echo: bytes
    cipher_suite: CipherSuite
    extensions: list[Extension]
    legacy_version: int = field(default=0x0303)
    legacy_compression_method: int = field(default=0)
    blocks: ClassVar[Blocks] = Blocks([
        Block(2, "byte", "int"),
        Block(32, "byte", "int"),
        Block(1, "byte", "raw", variable=True),
        Block(2, "byte", "int"),
        Block(1, "byte", "int"),
        Block(2, "byte", "raw", variable=True,
              after_parse=lambda ext: Extension.parse(ext, HandshakeType.server_hello))
    ], after_parse=lambda lv, r, lsie, cs, lcm, ext: ServerHello(
        legacy_version=lv, random=r,
        legacy_session_id_echo=lsie, cipher_suite=cs,
        legacy_compression_method=lcm, extensions=ext
    ))

    @staticmethod
    def make(ch: ClientHello):
        cipher_suite = ch.cipher_suites[0]
        return ServerHello(
            random=getRandomNBitInteger(32 * 8),
            legacy_session_id_echo=ch.legacy_session_id,
            cipher_suite=cipher_suite,
            extensions=[
                Extension(ExtensionType.supported_versions, SupportedVersions([0x0304])),
            ],
        )

    @staticmethod
    def parse(byte_seq: bytes):
        return ServerHello.blocks.from_byte(byte_seq)

    def unparse(self):
        bb = BytesBuilder()
        bb.append_int(self.legacy_version, 2)
        bb.append_int(self.random, 32)
        if self.legacy_session_id_echo is None:
            bb.append_int(0, 1)
        else:
            bb.append_variable_length(1, self.legacy_session_id_echo)
        bb.append_int(self.cipher_suite.value, 2)
        bb.append_int(self.legacy_compression_method, 1)
        ext_raw = b""
        for ext in self.extensions:
            ext_raw += ext.unparse(HandshakeType.server_hello)
        bb.append_int(len(ext_raw), 2)
        bb.append(ext_raw)
        return bb.to_bytes()
