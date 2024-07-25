from dataclasses import dataclass
from Crypto.Util.number import getRandomNBitInteger
from typing import ClassVar

from .cipher_suite import CipherSuite
from .client_hello import ClientHello

from extension import ExtensionParser
from extension.extension_data import ExtensionData
from extension.supported_versions import SupportedVersions
from common import HandshakeType
from reader import Blocks, Block

__all__ = ["ServerHello"]


@dataclass(frozen=True)
class ServerHello:
    legacy_version: int
    random: int
    legacy_session_id_echo: bytes
    cipher_suite: CipherSuite
    legacy_compression_method: int
    extensions: list[ExtensionData]
    blocks: ClassVar[Blocks] = Blocks([
        Block(2, "byte", "int"),
        Block(32, "byte", "int"),
        Block(1, "byte", "raw", variable=True),
        Block(2, "byte", "int"),
        Block(1, "byte", "int"),
        Block(2, "byte", "raw", variable=True,
              after_parse=lambda ext: ExtensionParser.parse(ext, HandshakeType.server_hello))
    ])

    # @staticmethod
    # def make(ch: ClientHello):
    #     cipher_suite = ch.cipher_suites[0]
    #     return ServerHello(
    #         legacy_version=0x0303,
    #         legacy_compression_method=0,
    #         random=getRandomNBitInteger(32 * 8),
    #         legacy_session_id_echo=ch.legacy_session_id,
    #         cipher_suite=cipher_suite,
    #         extensions=[
    #             SupportedVersions([0x0304]),
    #         ],
    #     )

    def unparse(self):
        ext_raw = ExtensionParser.unparse(self.extensions, HandshakeType.server_hello)
        return ServerHello.blocks.unparse(
            self.legacy_version, self.random,
            self.legacy_session_id_echo, self.cipher_suite.value,
            self.legacy_compression_method, ext_raw
        )


ServerHello.blocks.after_parse_factory = ServerHello
