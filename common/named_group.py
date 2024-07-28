from tls_object import TLSIntEnum
from enum import IntEnum


class NamedGroup(TLSIntEnum, IntEnum):
    # ECDHE
    secp256r1 = 0x0017
    secp384r1 = 0x0018
    secp521r1 = 0x0019
    x25519 = 0x001d
    x448 = 0x001e

    # DHE
    ffdhe2048 = 0x0100
    ffdhe3072 = 0x0101
    ffdhe4096 = 0x0102
    ffdhe6144 = 0x0103
    ffdhe8192 = 0x0104

    @classmethod
    def byte_length(cls) -> int:
        return 2
