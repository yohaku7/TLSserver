from .handshake import Handshake, HandshakeType

from .client_hello import ClientHello


class HandshakeParser:
    @staticmethod
    def parse(byte_seq: bytes) -> (Handshake, object):
        h, rest = Handshake.parse(byte_seq)
        handshake_message: object
        match h.msg_type:
            case HandshakeType.client_hello:
                handshake_message = ClientHello.parse(rest)
            case _:
                raise ValueError("未対応のハンドシェイクです！")
        return h, handshake_message
