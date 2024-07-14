# -*- coding: UTF-8 -*-
from dataclasses import dataclass
from typing import ClassVar

from reader import BytesReader, BytesBuilder, Blocks, Block
from common import HandshakeType
from .client_hello import ClientHello


@dataclass(frozen=True)
class Handshake:
    msg_type: HandshakeType
    length: int  # uint24
    message: object
    blocks: ClassVar[Blocks] = Blocks([
        Block(1, "byte", "int", after_parse=HandshakeType),
        Block(3, "byte", "int"),
    ])

    @staticmethod
    def parse(byte_seq: bytes):
        br = BytesReader(byte_seq)
        msg_type = br.read_byte(1, "int")
        msg_type = HandshakeType(msg_type)
        length = br.read_byte(3, "int")

        msg: object
        match msg_type:
            case HandshakeType.client_hello:
                msg = ClientHello.parse(br.rest_bytes())
            case _:
                raise ValueError("未対応のhandshakeです。")
        return Handshake(msg_type, length, msg)

    @staticmethod
    def make(msg_type: HandshakeType, handshake: object):
        bb = BytesBuilder()
        bb.append_int(msg_type.value, 1)
        msg_raw = handshake.unparse()
        msg_raw_len = len(msg_raw).to_bytes(3)
        bb.append(msg_raw_len + msg_raw)
        return bb.to_bytes()
