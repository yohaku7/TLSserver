from enum import IntEnum

from tls_object import TLSIntEnum


class ProtocolVersion(TLSIntEnum, IntEnum):
    TLS_1_2 = 0x0303
    TLS_1_3 = 0x0304

    @classmethod
    def byte_length(cls) -> int:
        return 2
