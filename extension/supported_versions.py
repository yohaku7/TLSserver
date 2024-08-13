from dataclasses import dataclass

from reader import new, BytesReader
from common import HandshakeType
from .extension_data import ExtensionReply


@dataclass(frozen=True)
class SupportedVersionsClientHello(new.TLSObject):
    version: list[int]

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            (1, True, 2)
        ]


@dataclass(frozen=True)
class SupportedVersionsServerHello(new.TLSObject):
    version: int

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            2
        ]


@dataclass(frozen=True)
class SupportedVersions:
    @classmethod
    def parse(cls, br: BytesReader, **additional_data):
        h_type = additional_data["handshake_type"]
        if h_type == HandshakeType.client_hello:
            return SupportedVersionsClientHello.parse(br)
        elif h_type == HandshakeType.server_hello:
            return SupportedVersionsServerHello.parse(br)
        else:
            raise ValueError("supported_versionsはこのハンドシェイクタイプには送信しないでください")

    @classmethod
    def from_bytes(cls, data: bytes, **additional_data):
        br = BytesReader(data)
        res = cls.parse(br, **additional_data)
        assert br.rest_length == 0
        return res

    def reply(self) -> ExtensionReply:
        assert 0x0304 in self.version  # TLS 1.3
        return ExtensionReply("Supported Version: 0x0304 (TLS 1.3)",
                              SupportedVersionsServerHello(0x0304))
