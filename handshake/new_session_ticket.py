from dataclasses import dataclass

from common import HandshakeType
from extension.extension_parser import ExtensionHeader
from reader import new

__all__ = ["NewSessionTicket"]


@dataclass(frozen=True)
class NewSessionTicket(new.TLSObject):
    ticket_lifetime: int
    ticket_age_add: int
    ticket_nonce: bytes
    ticket: bytes
    extensions: list[ExtensionHeader]

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            4,
            4,
            (1, True),
            (2, True),
            (2, True, None, {
                "handshake_type": HandshakeType.new_session_ticket,
            })
        ]
