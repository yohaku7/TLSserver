from dataclasses import dataclass

from common import NamedGroup, HandshakeType
from reader import new, BytesReader

__all__ = [
    "KeyShare", "KeyShareServerHello", "KeyShareHelloRetryRequest", "KeyShareClientHello",
    "KeyShareEntry"
]


@dataclass(frozen=True)
class KeyShareEntry(new.TLSObject):
    group: NamedGroup
    key_exchange: bytes

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            2,
            (2, True),
        ]


@dataclass(frozen=True)
class KeyShareClientHello(new.TLSObject):
    client_shares: list[KeyShareEntry]

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            (2, True),
        ]


@dataclass(frozen=True)
class KeyShareHelloRetryRequest(new.TLSObject):
    selected_group: NamedGroup

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            2
        ]


@dataclass(frozen=True)
class KeyShareServerHello(new.TLSObject):
    server_share: KeyShareEntry

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            None
        ]


class KeyShare:
    @classmethod
    def parse(cls, br: BytesReader, **additional_data):
        h_type = additional_data["handshake_type"]
        if h_type == HandshakeType.client_hello:
            return KeyShareClientHello.parse(br)
        elif h_type == HandshakeType.server_hello:
            return KeyShareServerHello.parse(br)

    @classmethod
    def from_bytes(cls, data: bytes, **additional_data):
        br = BytesReader(data)
        res = cls.parse(br, **additional_data)
        assert br.rest_length == 0
        return res
