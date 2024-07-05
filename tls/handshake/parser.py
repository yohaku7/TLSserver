from reader import BytesReader

from .handshake import Handshake, HandshakeType

from .client_hello import ClientHello


class HandshakeParser:
    @staticmethod
    def parse(byte_seq: bytes):
        h, r = Handshake.parse(byte_seq)
        match h.msg_type:
            case HandshakeType.client_hello:
                c = ClientHello.parse(r)
            case _:
                raise ValueError("未対応のハンドシェイクです！")
