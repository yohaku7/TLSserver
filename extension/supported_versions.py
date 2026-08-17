from dataclasses import dataclass

from common import HandshakeType, ProtocolVersion
from reader import BytesReader, new


@dataclass(frozen=True)
class SupportedVersionsClientHello(new.TLSObject):
    version: list[ProtocolVersion]

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            (1, True, 2)
        ]


@dataclass(frozen=True)
class SupportedVersionsServerHello(new.TLSObject):
    version: ProtocolVersion

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
