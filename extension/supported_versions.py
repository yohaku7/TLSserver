from dataclasses import dataclass

from reader import Block, ListBlock
from common import HandshakeType, ExtensionType
from .extension_data import ExtensionData


@dataclass(frozen=True)
class SupportedVersions(ExtensionData):
    version: list[int]

    @property
    def type(self) -> ExtensionType:
        return ExtensionType.supported_versions

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        version: list[int]
        match handshake_type:
            case HandshakeType.client_hello:
                version = ListBlock(1, 2, "byte", "int", variable=True).from_bytes(byte_seq)
            case HandshakeType.server_hello:  # and HelloRetryRequest
                version = [Block(2, "byte", "int").from_bytes(byte_seq)]
            case _:
                raise ValueError("supported_versionsはこのハンドシェイクタイプには送信しないでください")
        return SupportedVersions(version)

    def unparse(self, handshake_type: HandshakeType):
        if handshake_type == HandshakeType.client_hello:
            return ListBlock(1, 2, "byte", "int", variable=True).unparse(self.version)
        elif handshake_type == HandshakeType.server_hello:
            assert len(self.version) == 1
            return Block(2, "byte", "int").unparse(self.version[0])
        else:
            raise ValueError("supported_versionsをunparseできないhandshake_typeです")
