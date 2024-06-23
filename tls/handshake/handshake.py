# -*- coding: UTF-8 -*-
from __future__ import annotations

from enum import IntEnum
from dataclasses import dataclass

from tls.handshake_message import HandshakeMessage
from reader.bytes_reader import BytesReader
from tls.client_hello import ClientHello


class HandshakeType(IntEnum):
    client_hello = 1
    server_hello = 2
    new_session_ticket = 4
    end_of_early_data = 5
    encrypted_extensions = 8
    certificate = 11
    certificate_request = 13
    certificate_verify = 15
    finished = 20
    key_update = 24
    message_hash = 254
    # 255


@dataclass
class Handshake:
    msg_type: HandshakeType
    length: int  # uint24
    message: HandshakeMessage

    @staticmethod
    def parse(byte_seq: bytes) -> (Handshake, bytes):
        br = BytesReader(byte_seq)
        msg_type = br.read_byte(1, "int")
        msg_type = HandshakeType(msg_type)
        length = br.read_byte(3, "int")
        message = Handshake.__message_parse(msg_type, br.rest_bytes())

        return Handshake(msg_type, length, message), br.rest_bytes()

    @staticmethod
    def __message_parse(msg_type: HandshakeType, byte_seq: bytes) -> HandshakeMessage:
        match msg_type:
            case HandshakeType.client_hello:
                return ClientHello.parse(byte_seq)
            case _:
                raise ValueError("Handshakeの内容をパースできません。")
