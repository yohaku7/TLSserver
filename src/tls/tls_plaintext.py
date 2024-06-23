# -*- coding: UTF-8 -*-
from __future__ import annotations

from enum import IntEnum
from dataclasses import dataclass
from src.reader.bytes_reader import BytesReader


__all__ = [
    "ContentType",
    "TLSPlaintext"
]


class ContentType(IntEnum):
    invalid = 0
    change_cipher_spec = 20
    alert = 21
    handshake = 22
    application_data = 23
    # 255


@dataclass
class TLSPlaintext:
    """RFC8446 §5.1 の、fragmentを除いた部分。"""
    type: ContentType
    legacy_record_version: int
    length: int

    @staticmethod
    def parse(byte_seq: bytes) -> (TLSPlaintext, bytes):
        br = BytesReader(byte_seq)
        content_type = br.read_byte(1, "int")
        legacy_record_version = br.read_byte(2, "int")
        length = br.read_byte(2, "int")
        fragment = br.rest_bytes()
        return TLSPlaintext(ContentType(content_type), legacy_record_version, length), fragment
