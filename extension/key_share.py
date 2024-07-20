from dataclasses import dataclass
from typing import ClassVar

from common import NamedGroup, HandshakeType, ExtensionType
from reader import BytesReader, Block, Blocks
from .extension_data import ExtensionData

__all__ = [
    "KeyShare", "KeyShareServerHello", "KeyShareHelloRetryRequest", "KeyShareClientHello"
]


@dataclass(frozen=True)
class KeyShareEntry:
    group: NamedGroup
    key_exchange: bytes
    blocks: ClassVar[Blocks] = Blocks([
        Block(2, "byte", "int", after_parse=NamedGroup),
        Block(2, "byte", "raw", variable=True)
    ], after_parse=lambda g, k: KeyShareEntry(g, k))


@dataclass(frozen=True)
class KeyShareClientHello(ExtensionData):
    client_shares: list[KeyShareEntry]

    @property
    def type(self) -> ExtensionType:
        return ExtensionType.key_share

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        br = BytesReader(Block(2, "byte", "raw", variable=True).from_bytes(byte_seq))
        res = []
        while br.rest_length != 0:
            key_share_entry = KeyShareEntry.blocks.parse(br)
            res.append(key_share_entry)
        return KeyShareClientHello(res)

    def unparse(self, handshake_type: HandshakeType) -> bytes:
        res = b""
        for client_share in self.client_shares:
            res += KeyShareEntry.blocks.unparse(client_share.group, client_share.key_exchange)
        res = Block(2, "byte", "raw", variable=True).unparse(res)
        return res


@dataclass(frozen=True)
class KeyShareHelloRetryRequest(ExtensionData):
    selected_group: NamedGroup
    __blocks: ClassVar[Blocks] = Blocks([
        Block(2, "byte", "int", after_parse=NamedGroup)
    ], after_parse=lambda g: KeyShareHelloRetryRequest(g))

    @property
    def type(self) -> ExtensionType:
        return ExtensionType.key_share

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        return KeyShareHelloRetryRequest.__blocks.from_bytes(byte_seq)

    def unparse(self, handshake_type: HandshakeType) -> bytes:
        return KeyShareHelloRetryRequest.__blocks.unparse(self.selected_group)


@dataclass(frozen=True)
class KeyShareServerHello(ExtensionData):
    server_share: KeyShareEntry
    __blocks: ClassVar[Blocks] = Blocks([
        Block(2, "byte", "int", after_parse=NamedGroup),
        Block(2, "byte", "raw", variable=True)
    ], after_parse=lambda n, r: KeyShareServerHello(KeyShareEntry(n, r)))

    @property
    def type(self) -> ExtensionType:
        return ExtensionType.key_share

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        return KeyShareServerHello.__blocks.from_bytes(byte_seq)

    def unparse(self, handshake_type: HandshakeType) -> bytes:
        return KeyShareServerHello.__blocks.unparse(
            self.server_share.group, self.server_share.key_exchange
        )


class KeyShare:
    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        match handshake_type:
            case HandshakeType.client_hello:
                return KeyShareClientHello.parse(byte_seq, handshake_type)
            case HandshakeType.server_hello:
                return KeyShareServerHello.parse(byte_seq, handshake_type)
            case _:
                raise ValueError("key_shareをパースできません")
