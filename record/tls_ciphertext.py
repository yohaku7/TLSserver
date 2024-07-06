from .content_type import ContentType
from dataclasses import dataclass, field


@dataclass
class TLSCiphertext:
    length: int
    encrypted_record: bytes
    type: ContentType = field(default=ContentType.application_data)
    legacy_record_version: int = field(default=0x0303)

    @staticmethod
    def parse(byte_seq: bytes):
        pass
