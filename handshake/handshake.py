# -*- coding: UTF-8 -*-
from dataclasses import dataclass
from typing import ClassVar

from reader import Blocks, Block
from common import HandshakeType

__all__ = ["Handshake"]


@dataclass(frozen=True)
class Handshake:
    msg_type: HandshakeType
    length: int
    blocks: ClassVar[Blocks] = Blocks([
        Block(1, "byte", "int", after_parse=HandshakeType),
        Block(3, "byte", "int"),
    ])


Handshake.blocks.after_parse_factory = Handshake
