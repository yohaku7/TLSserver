from enum import IntEnum


class ContentType(IntEnum):
    invalid = 0
    change_cipher_spec = 20
    alert = 21
    handshake = 22
    application_data = 23
    # 255
