# -*- coding: UTF-8 -*-
from dataclasses import dataclass

from reader.bytes_reader import BytesReader
from common import HandshakeType
from .client_hello import ClientHello


@dataclass
class Handshake:
    msg_type: HandshakeType
    length: int  # uint24
    message: object

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
