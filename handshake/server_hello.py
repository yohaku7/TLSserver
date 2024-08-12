from dataclasses import dataclass
from typing import ClassVar

from extension.extension_parser import ExtensionHeader
from reader.new import BytesConverter, BytesConvertable
from .cipher_suite import CipherSuite
from .tls_handshake import TLSHandshake
from extension import ExtensionParser
from extension.extension_data import ExtensionData
from common import HandshakeType
from reader import Blocks, Block, new

__all__ = ["ServerHello"]


@dataclass(frozen=True)
class ServerHello(new.TLSObject):
    legacy_version: int
    random: int
    legacy_session_id_echo: bytes
    cipher_suite: CipherSuite
    legacy_compression_method: int
    extensions: list[ExtensionHeader]
    # blocks: ClassVar[Blocks] = Blocks([
    #     Block(2, "int"),
    #     Block(32, "int"),
    #     Block(1, "raw", variable=True),
    #     Block(2, "int"),
    #     Block(1, "int"),
    #     Block(2, "raw", variable=True,
    #           after_parse=lambda ext: ExtensionParser.parse(ext, HandshakeType.server_hello))
    # ])

    @classmethod
    def _get_lengths(cls) -> list[BytesConverter | BytesConvertable]:
        return [
            new.Block(2),
            new.Block(32),
            new.Block(new.Variable(1)),
            new.Block(2),
            new.Block(1),
            new.Block(new.Variable(2), additional_data={
                "handshake_type": HandshakeType.server_hello,
            })
        ]

    # def unparse(self):
    #     ext_raw = ExtensionParser.unparse(self.extensions, HandshakeType.server_hello)
    #     return ServerHello.unparse(
    #         self.legacy_version, self.random,
    #         self.legacy_session_id_echo, self.cipher_suite.value,
    #         self.legacy_compression_method, ext_raw
    #     )


# ServerHello.blocks.after_parse_factory = ServerHello
