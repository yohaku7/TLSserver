# -*- coding: UTF-8 -*-
# RFC8446 §4.1.2 に基づいたClientHelloとエンコードされた実際のメッセージ（バイト列）。
from dataclasses import dataclass
from src.reader.bytes_reader import BytesReader
from src.tls.extension import Extension
from src.tls.handshake_message import HandshakeMessage


@dataclass
class ClientHello(HandshakeMessage):
    legacy_version: int  # uint16; 16bit unsigned int
    random: int  # 32byte integer
    legacy_session_id: int
    cipher_suites: str
    legacy_compression_methods: int  # On TLS 1.3, this vector MUST contain exactly one byte, set to zero.
    extensions: list[Extension]

    @staticmethod
    def parse(byte_seq: bytes) -> ("ClientHello", bytes):
        br = BytesReader(byte_seq)
        legacy_version = br.read_byte(2, "int")
        random = br.read_byte(32, "int")
        legacy_session_id = br.read_variable_length(1, "int")
        cipher_suites = br.read_variable_length(2, "hex")
        legacy_compression_methods = br.read_variable_length(1, "int")
        extensions = br.read_variable_length(2, "hex")
        # extensions = Extension.parse(extensions)  # TODO: extensionsのパース
        return ClientHello(legacy_version,
                           random,
                           legacy_session_id,
                           cipher_suites,
                           legacy_compression_methods,
                           extensions), br.rest_bytes()
