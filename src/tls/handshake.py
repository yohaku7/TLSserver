# -*- coding: UTF-8 -*-
from enum import IntEnum
from dataclasses import dataclass

from src.tls.handshake_message import HandshakeMessage
from src.reader.bytes_reader import BytesReader
from src.tls.client_hello import ClientHello


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

    @staticmethod
    def parse(byte_seq: bytes) -> ("Handshake", bytes):
        br = BytesReader(byte_seq)
        msg_type = br.read_byte(1, "int")
        msg_type = HandshakeType(msg_type)
        length = br.read_byte(3, "int")
        message = br.rest_bytes()

        return Handshake(msg_type, length), message
