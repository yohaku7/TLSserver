from dataclasses import dataclass, field
from Crypto.Util.number import getRandomNBitInteger

from .cipher_suite import CipherSuite
from .client_hello import ClientHello

from extension.extension import Extension
from extension.supported_versions import SupportedVersions
from common import ExtensionType, HandshakeType
from reader import BytesBuilder, BytesReader


@dataclass
class ServerHello:
    random: int
    legacy_session_id_echo: bytes
    cipher_suite: CipherSuite
    extensions: list[Extension]
    legacy_version: int = field(default=0x0303)
    legacy_compression_method: int = field(default=0)

    @staticmethod
    def make(ch: ClientHello):
        cipher_suite = ch.cipher_suites[0]
        return ServerHello(
            random=getRandomNBitInteger(32 * 8),
            legacy_session_id_echo=ch.legacy_session_id,
            cipher_suite=cipher_suite,
            extensions=[
                Extension(ExtensionType.supported_versions, SupportedVersions([0x0304])),
            ],
        )

    @staticmethod
    def parse(byte_seq: bytes):
        br = BytesReader(byte_seq)
        legacy_version = br.read_byte(2, "int")
        random = br.read_byte(32, "int")
        legacy_session_id_echo = br.read_variable_length(1, "raw")
        cipher_suite = CipherSuite(br.read_byte(2, "int"))
        legacy_compression_method = br.read_byte(1, "int")
        extensions = Extension.parse(br.read_variable_length(2, "raw"), HandshakeType.server_hello)
        return ServerHello(
            legacy_version=legacy_version,
            random=random,
            legacy_session_id_echo=legacy_session_id_echo,
            cipher_suite=cipher_suite,
            legacy_compression_method=legacy_compression_method,
            extensions=extensions
        )

    def unparse(self):
        bb = BytesBuilder()
        bb.append_int(self.legacy_version, 2)
        bb.append_int(self.random, 32)
        if self.legacy_session_id_echo is None:
            bb.append_int(0, 1)
        else:
            bb.append_variable_length(1, self.legacy_session_id_echo)
        bb.append_int(self.cipher_suite.value, 2)
        bb.append_int(self.legacy_compression_method, 1)
        ext_raw = b""
        for ext in self.extensions:
            ext_raw += ext.unparse(HandshakeType.server_hello)
        bb.append_int(len(ext_raw), 2)
        bb.append(ext_raw)
        return bb.to_bytes()
