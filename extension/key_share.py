from dataclasses import dataclass
from typing import ClassVar

from common import NamedGroup, HandshakeType
from reader import BytesReader, Block, Blocks

__all__ = [
    "KeyShare", "KeyShareServerHello", "KeyShareHelloRetryRequest", "KeyShareClientHello"
]


@dataclass(frozen=True)
class KeyShareEntry:
    group: NamedGroup
    key_exchange: bytes


@dataclass(frozen=True)
class KeyShareClientHello:
    client_shares: list[KeyShareEntry]
    blocks: ClassVar[Blocks] = Blocks([
        Block(2, "byte", "int", after_parse=NamedGroup),
        Block(2, "byte", "raw", variable=True)
    ], after_parse=KeyShareEntry)

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        br = BytesReader(byte_seq)
        client_shares_raw = Block(2, "byte", "raw", variable=True).parse(br)
        br = BytesReader(client_shares_raw)
        res = []
        while br.rest_length != 0:
            key_share_entry = KeyShareClientHello.blocks.parse(br)
            res.append(key_share_entry)
        return KeyShareClientHello(res)


@dataclass(frozen=True)
class KeyShareHelloRetryRequest:
    selected_group: NamedGroup
    blocks: ClassVar[Blocks] = Blocks([
        Block(2, "byte", "int", after_parse=NamedGroup)
    ], after_parse=lambda g: KeyShareHelloRetryRequest(g))

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        return KeyShareHelloRetryRequest.blocks.from_byte(byte_seq)


@dataclass(frozen=True)
class KeyShareServerHello:
    server_share: KeyShareEntry

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        br = BytesReader(byte_seq)
        group = NamedGroup(br.read_byte(2, "int"))
        key_exchange = br.read_variable_length(2, "raw")
        return KeyShareServerHello(KeyShareEntry(group, key_exchange))


class KeyShare:
    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        match handshake_type:
            case HandshakeType.client_hello:
                return KeyShareClientHello.parse(byte_seq, handshake_type)
            case HandshakeType.server_hello:
                return KeyShareServerHello.parse(byte_seq, handshake_type)
            case _:
                raise ValueError("HelloRetryRequestですか？key_shareのパースはできません")
