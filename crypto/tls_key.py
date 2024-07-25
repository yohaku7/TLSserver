import math

from common import NamedGroup, HandshakeType
from extension.key_share import KeyShareEntry
from handshake import ClientHello, ServerHello, Handshake
from reader import Blocks, Block

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.hmac import HMAC, hashes
from Crypto.Util.number import long_to_bytes


SHA256_HASH_LEN: int = 32


class TLSKey:
    def __init__(self):
        self.x25519_shared_key: bytes = None
        self.client_x25519_public_key: X25519PublicKey = None
        self.server_x25519_private_key: X25519PrivateKey = None
        self.server_x25519_public_key: X25519PublicKey = None
        self.binder_key: bytes = None

    def exchange_key_x25519(self, entry: KeyShareEntry):
        assert entry.group == NamedGroup.x25519
        self.client_x25519_public_key = X25519PublicKey.from_public_bytes(entry.key_exchange)
        self.server_x25519_private_key = X25519PrivateKey.generate()
        self.server_x25519_public_key = self.server_x25519_private_key.public_key()
        self.x25519_shared_key = self.server_x25519_private_key.exchange(self.client_x25519_public_key)

    @staticmethod
    def HKDF_Extract(salt: bytes, ikm: bytes) -> bytes:
        # RFC5869 §2.2
        hmac = HMAC(salt, hashes.SHA256())
        hmac.update(ikm)
        return hmac.finalize()

    @staticmethod
    def HKDF_Expand(extracted_key: bytes, context: bytes, length: int) -> bytes:
        # RFC5869 §2.3
        def _T(n: int):
            if n == 0:
                return b""
            else:
                hmac = HMAC(extracted_key, hashes.SHA256())
                hmac.update(_T(n - 1) + context + long_to_bytes(n))
                return hmac.finalize()
        N = math.ceil(length / SHA256_HASH_LEN)
        T = b""
        for n in range(1, N + 1):
            T += _T(n)
        return T[:length]

    @staticmethod
    def HKDF_Expand_Label(secret: bytes, label: bytes, context: bytes, length: int):
        # https://tex2e.github.io/rfc-translater/html/rfc8446.html#7-1--Key-Schedule
        hkdf_label = Blocks([
            Block(2, "byte", "int"),
            Block(1, "byte", "raw", variable=True),
            Block(1, "byte", "raw", variable=True)
        ]).unparse(
            length, b"tls13 " + label, context
        )
        return TLSKey.HKDF_Expand(secret, hkdf_label, length)

    @staticmethod
    def Transcript_Hash(*M: ClientHello | ServerHello):
        # RFC8446 §4.4.1
        sha256 = hashes.Hash(hashes.SHA256())
        raw = b""
        for m in M:
            if isinstance(m, ClientHello):
                hs = Handshake(HandshakeType.client_hello, len(m.unparse()))
            elif isinstance(m, ServerHello):
                hs = Handshake(HandshakeType.server_hello, len(m.unparse()))
            else:
                raise ValueError("Can't calc Transcript-Hash")
            raw += Handshake.blocks.unparse(hs) + m.unparse()
        sha256.update(raw)
        return sha256.finalize()

    @staticmethod
    def Derive_Secret(secret: bytes, label: bytes, *messages: ClientHello | ServerHello):
        return TLSKey.HKDF_Expand_Label(
            secret, label, TLSKey.Transcript_Hash(*messages), SHA256_HASH_LEN
        )


def main():
    # お借りしました: https://github.com/elliptic-shiho/tls13/blob/816fb6ee584965806ecbb9ecab249fd45e07c702/src/tls/crypto/cipher_suite.rs#L204-L219
    initial_secret = bytes.fromhex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")
    client_initial_secret = bytes.fromhex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
    actual = TLSKey.HKDF_Expand_Label(
        initial_secret, b"client in", b"", SHA256_HASH_LEN
    )
    assert client_initial_secret == actual


if __name__ == '__main__':
    main()
