# -*- coding: UTF-8 -*-
# RFC8446 §4.1.2 に基づいたClientHelloとエンコードされた実際のメッセージ（バイト列）。
from dataclasses import dataclass, field
from reader.bytes_reader import BytesReader
from tls.extension import Extension


@dataclass
class ClientHello:
    legacy_version: int  # uint16
    random: int  # 32byte integer
    legacy_session_id: int
    cipher_suites: str
    extensions: list[Extension]
    legacy_compression_methods: int = field(default=0)

    @staticmethod
    def parse(byte_seq: bytes) -> ("ClientHello", bytes):
        br = BytesReader(byte_seq)
        legacy_version = br.read_byte(2, "int")
        random = br.read_byte(32, "int")
        legacy_session_id = br.read_variable_length(1, "int")
        cipher_suites = br.read_variable_length(2, "hex")
        legacy_compression_methods = br.read_variable_length(1, "int")

        extensions = br.read_variable_length(2, "raw")
        extensions = Extension.parse(extensions)
        c = ClientHello(legacy_version,
                        random,
                        legacy_session_id,
                        cipher_suites,
                        extensions,
                        legacy_compression_methods=legacy_compression_methods), br.rest_bytes()

        print(c)
        return c
