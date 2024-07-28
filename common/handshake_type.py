from tls_object import TLSIntEnum
from enum import IntEnum


class HandshakeType(TLSIntEnum, IntEnum):
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

    @classmethod
    def byte_length(cls) -> int:
        return 1
