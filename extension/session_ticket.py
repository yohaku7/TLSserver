from dataclasses import dataclass

from reader import BytesReader


@dataclass
class SessionTicket:
    ticket: bytes | None

    @staticmethod
    def parse(byte_seq: bytes):
        if byte_seq is None:
            return SessionTicket(None)
        br = BytesReader(byte_seq)
        return SessionTicket(br.read_variable_length(2, "raw"))
