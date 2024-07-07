from dataclasses import dataclass

from reader import BytesReader
from common import HandshakeType


@dataclass
class SupportedVersions:
    version: list[int] | int

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        br = BytesReader(byte_seq)
        version: list[int] | int
        match handshake_type:
            case HandshakeType.client_hello:
                version = br.read_variable_length_per(1, 2, "int")
            case HandshakeType.server_hello:  # and HelloRetryRequest
                version = br.read_byte(2, "int")
            case _:
                raise ValueError("supported_versionsはこのハンドシェイクタイプには送信しないでください")
        return SupportedVersions(version)
