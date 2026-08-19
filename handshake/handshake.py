# -*- coding: UTF-8 -*-
from dataclasses import dataclass

from alert import Alert, AlertLevel, AlertDescription
from common import HandshakeType
from handshake.certificate import Certificate
from handshake.certificate_verify import CertificateVerify
from handshake.client_hello import ClientHello
from handshake.encrypted_extensions import EncryptedExtensions
from handshake.end_of_early_data import EndOfEarlyData
from handshake.finished import Finished
from handshake.new_session_ticket import NewSessionTicket
from handshake.server_hello import ServerHello
from reader import new

__all__ = ["Handshake", "TLSHandshake"]

from reader.validation_result import ValidationResult

handshake_type: dict[type[new.TLSObject], HandshakeType] = {
    ServerHello: HandshakeType.server_hello,
    ClientHello: HandshakeType.client_hello,
    EncryptedExtensions: HandshakeType.encrypted_extensions,
    Certificate: HandshakeType.certificate,
    CertificateVerify: HandshakeType.certificate_verify,
    Finished: HandshakeType.finished,
    NewSessionTicket: HandshakeType.new_session_ticket,
    EndOfEarlyData: HandshakeType.end_of_early_data,
}


@dataclass(frozen=True)
class TLSHandshake:
    msg_type: int
    length: int
    msg: bytes

    @classmethod
    def from_bytes(cls, data: bytes):
        return TLSHandshake(
            msg_type=int.from_bytes(data[0:1], byteorder="big"),
            length=int.from_bytes(data[1:4], byteorder="big"),
            msg=data[4:],
        )

    def to_bytes(self) -> bytes:
        return (int.to_bytes(self.msg_type, 1)
                + int.to_bytes(self.length, 3)
                + self.msg)

    def validate(self) -> ValidationResult["TLSHandshake"]:
        if self.msg_type not in HandshakeType:
            return ValidationResult.failure(
                Alert(AlertLevel.fatal, AlertDescription.illegal_parameter),
            )
        return ValidationResult.success(self)


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
