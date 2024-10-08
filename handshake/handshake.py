# -*- coding: UTF-8 -*-
from dataclasses import dataclass

from handshake.certificate_verify import CertificateVerify
from handshake.finished import Finished
from handshake.server_hello import ServerHello
from handshake.client_hello import ClientHello
from handshake.encrypted_extensions import EncryptedExtensions
from handshake.certificate import Certificate
from reader import new
from common import HandshakeType

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
