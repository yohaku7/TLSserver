# -*- coding: UTF-8 -*-
from dataclasses import dataclass
from typing import ClassVar

from reader import Blocks, Block, RestBlock
from common import HandshakeType
from .client_hello import ClientHello
from .server_hello import ServerHello

__all__ = ["Handshake"]


def _make(msg_type, length, message_raw):
    match msg_type:
        case HandshakeType.client_hello:
            message = ClientHello.parse(message_raw)
        case HandshakeType.server_hello:
            message = ServerHello.parse(message_raw)
        case _:
            raise ValueError("Unsupported handshake")
    return Handshake(msg_type, length, message)


@dataclass(frozen=True)
class Handshake:
    msg_type: HandshakeType
    length: int
    message: object
    __blocks: ClassVar[Blocks] = Blocks([
        Block(1, "byte", "int", after_parse=HandshakeType),
        Block(3, "byte", "int"),
        RestBlock("raw")
    ], after_parse=_make)

    @staticmethod
    def parse(byte_seq: bytes):
        return Handshake.__blocks.from_bytes(byte_seq)

    def unparse(self):
        return Handshake.__blocks.unparse(self.msg_type, self.length, self.message.unparse())
