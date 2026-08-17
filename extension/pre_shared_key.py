from dataclasses import dataclass

from common import HandshakeType
from reader import new, BytesReader

# RFC8446 §4.2.11 を参照。

__all__ = ["PreSharedKey", "PreSharedKeyClientHello", "PreSharedKeyServerHello", "PskIdentity", "PskBinderEntry"]


@dataclass(frozen=True)
class PskIdentity(new.TLSObject):
    identity: bytes
    obfuscated_ticket_age: int

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            (2, True),
            4,
        ]


@dataclass(frozen=True)
class PskBinderEntry(new.TLSObject):
    psk_binder_entry: bytes

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            (1, True),
        ]


# 実体は OfferedPsks である。
@dataclass(frozen=True)
class PreSharedKeyClientHello(new.TLSObject):
    identities: list[PskIdentity]
    binders: list[PskBinderEntry]

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            (2, True),
            (2, True),
        ]


@dataclass(frozen=True)
class PreSharedKeyServerHello(new.TLSObject):
    selected_identity: int

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            2,
        ]


class PreSharedKey:
    @classmethod
    def parse(cls, br: BytesReader, **additional_data):
        h_type = additional_data["handshake_type"]
        if h_type == HandshakeType.client_hello:
            return PreSharedKeyClientHello.parse(br)
        elif h_type == HandshakeType.server_hello:
            return PreSharedKeyServerHello.parse(br)

    @classmethod
    def from_bytes(cls, data: bytes, **additional_data):
        br = BytesReader(data)
        res = cls.parse(br, **additional_data)
        assert br.rest_length == 0
        return res
