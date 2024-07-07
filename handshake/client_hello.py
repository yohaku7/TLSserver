# -*- coding: UTF-8 -*-
# RFC8446 §4.1.2 に基づいたClientHelloとエンコードされた実際のメッセージ（バイト列）。
from dataclasses import dataclass, field

from .cipher_suite import CipherSuite
from reader.bytes_reader import BytesReader
from extension import Extension
from common import HandshakeType


@dataclass
class ClientHello:
    legacy_version: int  # uint16
    random: int  # 32byte integer
    legacy_session_id: int
    cipher_suites: list[CipherSuite]
    extensions: list[Extension]
    legacy_compression_methods: int = field(default=0)

    @staticmethod
    def parse(byte_seq: bytes) -> ("ClientHello", bytes):
        br = BytesReader(byte_seq)
        legacy_version = br.read_byte(2, "int")
        random = br.read_byte(32, "int")
        legacy_session_id = br.read_variable_length(1, "int")

        cipher_suites = br.read_variable_length_per(2, 2, "int")
        cipher_suites = list(map(CipherSuite, cipher_suites))

        legacy_compression_methods = br.read_variable_length(1, "int")

        extensions = br.read_variable_length(2, "raw")
        extensions = Extension.parse(extensions, HandshakeType.client_hello)
        return ClientHello(legacy_version,
                           random,
                           legacy_session_id,
                           cipher_suites,
                           extensions,
                           legacy_compression_methods=legacy_compression_methods), br.rest_bytes()

        # c = ClientHello(legacy_version,
        #                    random,
        #                    legacy_session_id,
        #                    cipher_suites,
        #                    [],
        #                    legacy_compression_methods=legacy_compression_methods), br.rest_bytes()
        # print(c)
