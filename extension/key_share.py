from dataclasses import dataclass
from typing import ClassVar

from common import NamedGroup, HandshakeType
from reader import Block, Blocks, BlocksLoop, from_bytes
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
    ])


KeyShareEntry.blocks.after_parse_factory = KeyShareEntry


@dataclass(frozen=True)
class KeyShareClientHello(ExtensionData):
    client_shares: list[KeyShareEntry]
    blocks = Blocks([
        BlocksLoop(KeyShareEntry.blocks)
    ], variable=True, variable_header_size=2)


KeyShareClientHello.blocks.after_parse_factory = KeyShareClientHello


@dataclass(frozen=True)
class KeyShareHelloRetryRequest(ExtensionData):
    selected_group: NamedGroup
    blocks = Blocks([
        Block(2, "byte", "int", after_parse=NamedGroup)
    ])


KeyShareHelloRetryRequest.blocks.after_parse_factory = KeyShareHelloRetryRequest


@dataclass(frozen=True)
class KeyShareServerHello(ExtensionData):
    server_share: KeyShareEntry
    blocks = Blocks([
        KeyShareEntry.blocks
    ])


KeyShareServerHello.blocks.after_parse_factory = KeyShareServerHello


class KeyShare:
    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType):
        return from_bytes(
            handshake_type,
            {
                HandshakeType.client_hello: KeyShareClientHello.blocks,
                HandshakeType.server_hello: KeyShareServerHello.blocks
            },
            byte_seq
        )
