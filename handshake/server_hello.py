from dataclasses import dataclass

from alert import Alert, AlertLevel, AlertDescription
from common import HandshakeType
from extension.extension_parser import ExtensionHeader
from reader import new, BytesReader
from reader.validation_result import ValidationResult

from .cipher_suite import CipherSuite

__all__ = ["ServerHello"]


@dataclass(frozen=True)
class TLSServerHello:
    legacy_version: int
    random: bytes
    legacy_session_id_echo: bytes
    cipher_suite: int
    legacy_compression_method: int
    extensions: bytes

    @classmethod
    def from_bytes(cls, data: bytes):
        br = BytesReader(data)
        return TLSServerHello(
            legacy_version=br.read_byte(2, "int"),
            random=br.read_byte(32, "raw"),
            legacy_session_id_echo=br.read_variable_length(1, "raw"),
            cipher_suite=br.read_byte(1, "int"),
            legacy_compression_method=br.read_byte(1, "int"),
            extensions=br.read_variable_length(2, "raw"),
        )

    def to_bytes(self) -> bytes:
        legacy_session_id_echo_len = int.to_bytes(len(self.legacy_session_id_echo), 1)
        ext_length = int.to_bytes(len(self.extensions), 2)
        return (int.to_bytes(self.legacy_version, 2)
                + self.random
                + legacy_session_id_echo_len + self.legacy_session_id_echo
                + int.to_bytes(self.cipher_suite, 2)
                + int.to_bytes(self.legacy_compression_method, 1)
                + ext_length + self.extensions)

    def validate(self) -> ValidationResult["TLSServerHello"]:
        if self.legacy_compression_method != 0:
            return ValidationResult.failure(
                Alert(AlertLevel.fatal, AlertDescription.illegal_parameter)
            )
        return ValidationResult.success(self)


@dataclass(frozen=True)
class ServerHello(new.TLSObject):
    legacy_version: int
    random: int
    legacy_session_id_echo: bytes
    cipher_suite: CipherSuite
    legacy_compression_method: int
    extensions: list[ExtensionHeader]

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            2,
            32,
            (1, True),
            2,
            1,
            (2, True, None, {
                "handshake_type": HandshakeType.server_hello
            })
        ]
