# -*- coding: UTF-8 -*-
# RFC8446 §4.1.2 に基づいたClientHelloとエンコードされた実際のメッセージ（バイト列）。
from dataclasses import dataclass

from alert import Alert, AlertLevel, AlertDescription
from common import HandshakeType
from extension.extension_parser import ExtensionHeader
from reader import new, BytesReader
from reader.validation_result import ValidationResult
from .cipher_suite import CipherSuite

__all__ = ["ClientHello", "TLSClientHello"]


@dataclass(frozen=True)
class TLSClientHello:
    legacy_version: int
    random: bytes
    legacy_session_id: bytes
    cipher_suites: list[int]
    legacy_compression_methods: bytes
    extensions: bytes

    @classmethod
    def from_bytes(cls, data: bytes):
        br = BytesReader(data)
        return TLSClientHello(
            legacy_version=br.read_byte(2, "int"),
            random=br.read_byte(32, "raw"),
            legacy_session_id=br.read_variable_length(1, "raw"),
            cipher_suites=br.read_variable_length_per(2, 2, "int"),
            legacy_compression_methods=br.read_variable_length(1, "raw"),
            extensions=br.read_variable_length(2, "raw"),
        )

    def to_bytes(self) -> bytes:
        legacy_session_id_len = int.to_bytes(len(self.legacy_session_id), 1)
        cipher_suites_len = int.to_bytes(len(self.cipher_suites), 2)
        legacy_compression_methods_len = int.to_bytes(len(self.legacy_compression_methods), 1)
        extensions_len = int.to_bytes(len(self.extensions), 2)
        return (int.to_bytes(self.legacy_version, 2)
                + self.random
                + legacy_session_id_len + self.legacy_session_id
                + cipher_suites_len + b"".join([int.to_bytes(s, 2) for s in self.cipher_suites])
                + legacy_compression_methods_len + self.legacy_compression_methods
                + extensions_len + self.extensions)

    def validate(self) -> ValidationResult["TLSClientHello"]:
        if self.legacy_compression_methods != b"\x00":
            return ValidationResult.failure(
                Alert(AlertLevel.fatal, AlertDescription.illegal_parameter)
            )
        return ValidationResult.success(self)


@dataclass(frozen=True)
class ClientHello(new.TLSObject):
    legacy_version: int
    random: int
    legacy_session_id: bytes
    cipher_suites: list[CipherSuite]
    legacy_compression_methods: int
    extensions: list[ExtensionHeader]

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            2,
            32,
            (1, True),
            (2, True, 2),
            (1, True),
            (2, True, None, {
                "handshake_type": HandshakeType.client_hello,
            })
        ]
