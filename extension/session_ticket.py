from dataclasses import dataclass
from reader import new

# RFC8447, RFC5077 §3.2 を参照。

__all__ = ["SessionTicket"]


"""
If the client does not have a ticket and is prepared to receive one in the NewSessionTicket handshake message,
then it MUST include a zero-length ticket in the SessionTicket extension.
"""


@dataclass(frozen=True)
class SessionTicket(new.TLSObject):
    ticket: bytes

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            0
        ]
