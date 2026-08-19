from dataclasses import dataclass

from common import HandshakeType
from reader import BytesReader, new


@dataclass(frozen=True)
class EarlyDataIndicationClientHello(new.TLSObject):
    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return []


@dataclass(frozen=True)
class EarlyDataIndicationEncryptedExtensions(new.TLSObject):
    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return []


@dataclass(frozen=True)
class EarlyDataIndicationNewSessionTicket(new.TLSObject):
    max_early_data_size: int

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            4,
        ]


@dataclass(frozen=True)
class EarlyData:
    @classmethod
    def parse(cls, br: BytesReader, **additional_data):
        h_type = additional_data["handshake_type"]
        if h_type == HandshakeType.client_hello:
            return EarlyDataIndicationClientHello.parse(br)
        elif h_type == HandshakeType.encrypted_extensions:
            return EarlyDataIndicationEncryptedExtensions.parse(br)
        elif h_type == HandshakeType.new_session_ticket:
            return EarlyDataIndicationNewSessionTicket.parse(br)

    @classmethod
    def from_bytes(cls, data: bytes, **additional_data):
        br = BytesReader(data)
        res = cls.parse(br, **additional_data)
        assert br.rest_length == 0
        return res
