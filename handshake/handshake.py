# -*- coding: UTF-8 -*-
from dataclasses import dataclass

from common import HandshakeType
from handshake.certificate import Certificate
from handshake.certificate_verify import CertificateVerify
from handshake.client_hello import ClientHello
from handshake.encrypted_extensions import EncryptedExtensions
from handshake.finished import Finished
from handshake.server_hello import ServerHello
from reader import new

__all__ = ["Handshake"]


handshake_type: dict[type[new.TLSObject], HandshakeType] = {
    ServerHello: HandshakeType.server_hello,
    ClientHello: HandshakeType.client_hello,
    EncryptedExtensions: HandshakeType.encrypted_extensions,
    Certificate: HandshakeType.certificate,
    CertificateVerify: HandshakeType.certificate_verify,
    Finished: HandshakeType.finished,
}


@dataclass(frozen=True)
class Handshake(new.TLSObject):
    msg_type: HandshakeType
    length: int
    msg: bytes

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            1,
            3,
            -1
        ]

    @staticmethod
    def make(msg: new.TLSObject):
        if not type(msg) in handshake_type:
            raise ValueError("Handshakeをパースできません")
        msg_type = handshake_type[type(msg)]
        msg_raw = msg.unparse()
        length = len(msg_raw)
        return Handshake(msg_type, length, msg_raw)
