from dataclasses import dataclass

from reader import BytesBuilder, Block, ListBlock
from common import HandshakeType


@dataclass
class SupportedVersions:
    version: list[int]

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        version: list[int]
        match handshake_type:
            case HandshakeType.client_hello:
                version = ListBlock(1, 2, "byte", "int", True).from_byte(byte_seq)
            case HandshakeType.server_hello:  # and HelloRetryRequest
                version = [Block(2, "byte", "int").from_byte(byte_seq)]
            case _:
                raise ValueError("supported_versionsはこのハンドシェイクタイプには送信しないでください")
        return SupportedVersions(version)

    def unparse(self, handshake_type: HandshakeType):
        bb = BytesBuilder()
        if handshake_type == HandshakeType.client_hello:
            ver_raw = b""
            for ver in self.version:
                ver_raw += ver.to_bytes(2)
            bb.append(len(ver_raw).to_bytes(1) + ver_raw)
        elif handshake_type == HandshakeType.server_hello:
            assert len(self.version) == 1
            bb.append_int(self.version[0], 2)
        else:
            raise ValueError("supported_versionsをunparseできないhandshake_typeです")
        return bb.to_bytes()
