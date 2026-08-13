from enum import IntEnum

from tls_object import TLSIntEnum


class ContentType(TLSIntEnum, IntEnum):
    invalid = 0
    change_cipher_spec = 20
    alert = 21
    handshake = 22
    application_data = 23

    @classmethod
    def byte_length(cls) -> int:
        return 1
