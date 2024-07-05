# -*- coding: UTF-8 -*-
from dataclasses import dataclass

from reader.bytes_reader import BytesReader
from .handshake_type import HandshakeType


@dataclass
class Handshake:
    msg_type: HandshakeType
    length: int  # uint24

    @staticmethod
    def parse(byte_seq: bytes):
        br = BytesReader(byte_seq)
        msg_type = br.read_byte(1, "int")
        msg_type = HandshakeType(msg_type)
        length = br.read_byte(3, "int")

        return Handshake(msg_type, length), br.rest_bytes()
