from handshake import ClientHello, CipherSuite
from extension import Extension
from extension.server_name import ServerName
from extension.supported_groups import SupportedGroups
from extension.supported_versions import SupportedVersions
from extension.signature_algorithms import SignatureAlgorithms
from common import NamedGroup, SignatureScheme, ExtensionType


if __name__ == '__main__':
    c = ClientHello(
        legacy_version=0x0303,
        random=91913017918200322636149833828193042555529270961217949957241938725319929097447,
        legacy_session_id=0,
        cipher_suites=[CipherSuite.TLS_AES_256_GCM_SHA384, CipherSuite.TLS_CHACHA20_POLY1305_SHA256],
        extensions=[
            Extension(ExtensionType.server_name, ServerName("yohaku7.jp")),
            Extension(ExtensionType.supported_versions, SupportedVersions(0x0304)),
            Extension(ExtensionType.supported_groups, SupportedGroups([NamedGroup.x25519, NamedGroup.secp256r1, NamedGroup.secp384r1, NamedGroup.x448])),
            Extension(ExtensionType.signature_algorithms, SignatureAlgorithms([SignatureScheme.ed25519, SignatureScheme.rsa_pkcs1_sha256, SignatureScheme.ecdsa_secp256r1_sha256])),
        ],
        legacy_compression_methods=0
    )
    print(c.unparse())
