import math

from common import NamedGroup, ContentType
from extension.key_share import KeyShareEntry
from handshake import ClientHello, ServerHello, Handshake
from reader import Blocks, Block

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.hmac import HMAC, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509

from Crypto.Util.number import long_to_bytes


SHA256_HASH_LEN: int = 32


class TLSKey:
    def __init__(self):
        self.x25519_shared_key: bytes | None = None
        self.client_x25519_public_key: X25519PublicKey | None = None
        self.server_x25519_private_key: X25519PrivateKey | None = None
        self.server_x25519_public_key: X25519PublicKey | None = None
        self.binder_key: bytes | None = None
        self.client_early_traffic_secret: bytes | None = None
        self.early_exporter_master_secret: bytes | None = None
        self.client_handshake_traffic_secret: bytes | None = None
        self.server_handshake_traffic_secret: bytes | None = None

        self.seq_server: int = 0
        self.seq_client: int = 0

        self.__secret_state: bytes | None = None

        self.master_secret: bytes | None = None
        self.client_application_traffic_secret: list[bytes] = []
        self.server_application_traffic_secret: list[bytes] = []
        self.exporter_master_secret: bytes | None = None
        self.resumption_master_secret: bytes | None = None

    def exchange_key_x25519(self, entry: KeyShareEntry):
        assert entry.group == NamedGroup.x25519
        self.client_x25519_public_key = X25519PublicKey.from_public_bytes(entry.key_exchange)
        self.server_x25519_private_key = X25519PrivateKey.generate()
        self.server_x25519_public_key = self.server_x25519_private_key.public_key()
        self.x25519_shared_key = self.server_x25519_private_key.exchange(self.client_x25519_public_key)

    def derive_secrets(self, psk: bytes | None, ch: ClientHello, sh: ServerHello):
        if psk is None:
            psk = long_to_bytes(0, SHA256_HASH_LEN)
        else:
            assert len(psk) == SHA256_HASH_LEN
        early_secret = TLSKey.HKDF_Extract(long_to_bytes(0, SHA256_HASH_LEN), psk)
        self.binder_key = TLSKey.Derive_Secret(early_secret, b"ext binder")
        self.client_early_traffic_secret = TLSKey.Derive_Secret(early_secret, b"c e traffic", ch)
        self.early_exporter_master_secret = TLSKey.Derive_Secret(early_secret, b"e exp master", ch)

        secret_state = TLSKey.Derive_Secret(early_secret, b"derived")

        assert self.x25519_shared_key is not None

        handshake_secret = TLSKey.HKDF_Extract(secret_state, self.x25519_shared_key)
        self.client_handshake_traffic_secret = TLSKey.Derive_Secret(handshake_secret, b"c hs traffic", ch, sh)
        self.server_handshake_traffic_secret = TLSKey.Derive_Secret(handshake_secret, b"s hs traffic", ch, sh)
        print(f"sss: {self.server_handshake_traffic_secret.hex()}")

        secret_state = TLSKey.Derive_Secret(handshake_secret, b"derived")
        self.__secret_state = secret_state

    @staticmethod
    def HMAC(key: bytes, data: bytes):
        hmac = HMAC(key, hashes.SHA256())
        hmac.update(data)
        return hmac.finalize()

    @staticmethod
    def HKDF_Extract(salt: bytes, ikm: bytes) -> bytes:
        # RFC5869 §2.2
        return TLSKey.HMAC(salt, ikm)

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
            Block(2, "int"),
            Block(1, "raw", variable=True),
            Block(1, "raw", variable=True)
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
            hs = Handshake.make(m)
            raw += Handshake.blocks.unparse(hs)
        sha256.update(raw)
        return sha256.finalize()

    @staticmethod
    def Derive_Secret(secret: bytes, label: bytes, *messages: ClientHello | ServerHello):
        t_hash = TLSKey.Transcript_Hash(*messages)
        return TLSKey.HKDF_Expand_Label(secret, label, t_hash, SHA256_HASH_LEN)

    def encrypt_handshake(self, data: bytes, opaque_type: ContentType, legacy_record_version: int, length: int):
        # RFC5116 §5.1
        assert self.server_handshake_traffic_secret is not None
        write_key = TLSKey.HKDF_Expand_Label(self.server_handshake_traffic_secret, b"key", b"", 16)
        write_iv = TLSKey.HKDF_Expand_Label(self.server_handshake_traffic_secret, b"iv", b"", 12)
        aes128 = Cipher(algorithms.AES128(write_key), modes.GCM(self.calc_nonce(write_iv, "server")))
        encryptor = aes128.encryptor()
        encryptor.authenticate_additional_data(
            long_to_bytes(opaque_type) +
            long_to_bytes(legacy_record_version) +
            long_to_bytes(length, 2)  # RFC8446 §5.2
        )
        return encryptor.update(data) + encryptor.finalize(), encryptor.tag

    def decrypt_handshake(self, data: bytes, opaque_type: ContentType, legacy_record_version: int, length: int):
        tag = data[-16:]
        real_data = data[:-16]
        assert self.client_handshake_traffic_secret is not None
        write_key = TLSKey.HKDF_Expand_Label(self.client_handshake_traffic_secret, b"key", b"", 16)
        write_iv = TLSKey.HKDF_Expand_Label(self.client_handshake_traffic_secret, b"iv", b"", 12)
        aes128 = Cipher(algorithms.AES128(write_key), modes.GCM(self.calc_nonce(write_iv, "client")))
        decryptor = aes128.decryptor()
        decryptor.authenticate_additional_data(
            long_to_bytes(opaque_type) +
            long_to_bytes(legacy_record_version) +
            long_to_bytes(length, 2)  # RFC8446 §5.2
        )
        return decryptor.update(real_data) + decryptor.finalize_with_tag(tag)

    def encrypt_application_data(self, data: bytes, opaque_type: ContentType, legacy_record_version: int, length: int):
        assert self.server_application_traffic_secret[0] is not None
        write_key = TLSKey.HKDF_Expand_Label(self.server_application_traffic_secret[0], b"key", b"", 16)
        write_iv = TLSKey.HKDF_Expand_Label(self.server_application_traffic_secret[0], b"iv", b"", 12)
        aes128 = Cipher(algorithms.AES128(write_key), modes.GCM(self.calc_nonce(write_iv, "client")))
        encryptor = aes128.encryptor()
        encryptor.authenticate_additional_data(
            long_to_bytes(opaque_type) +
            long_to_bytes(legacy_record_version) +
            long_to_bytes(length, 2)  # RFC8446 §5.2
        )
        return encryptor.update(data) + encryptor.finalize()

    def decrypt_application_data(self, data: bytes, opaque_type: ContentType, legacy_record_version: int, length: int):
        tag = data[-16:]
        real_data = data[:-16]
        assert self.client_application_traffic_secret[0] is not None
        write_key = TLSKey.HKDF_Expand_Label(self.client_application_traffic_secret[0], b"key", b"", 16)
        write_iv = TLSKey.HKDF_Expand_Label(self.client_application_traffic_secret[0], b"iv", b"", 12)
        aes128 = Cipher(algorithms.AES128(write_key), modes.GCM(self.calc_nonce(write_iv, "client")))
        decryptor = aes128.decryptor()
        decryptor.authenticate_additional_data(
            long_to_bytes(opaque_type) +
            long_to_bytes(legacy_record_version) +
            long_to_bytes(length, 2)  # RFC8446 §5.2
        )
        return decryptor.update(real_data) + decryptor.finalize_with_tag(tag)

    def make_application_key(self, handshake_ctx, client_finished):
        self.master_secret = TLSKey.HKDF_Extract(self.__secret_state, b"\00" * 32)
        self.client_application_traffic_secret.append(
            TLSKey.Derive_Secret(self.master_secret, b"c ap traffic",
                                 *handshake_ctx)
        )
        self.server_application_traffic_secret.append(
            TLSKey.Derive_Secret(self.master_secret, b"s ap traffic",
                                 *handshake_ctx)
        )
        self.exporter_master_secret = TLSKey.Derive_Secret(self.master_secret, b"exp master", *handshake_ctx)
        self.resumption_master_secret = TLSKey.Derive_Secret(self.master_secret, b"res master",
                                                              *[*handshake_ctx, client_finished])

    def calc_nonce(self, write_iv: bytes, side: str):
        # RFC8446 §5.3, RFC5116 §5.1
        iv_length = 12  # RFC5116 §5.1
        if side == "server":
            seq_bin = long_to_bytes(self.seq_server, iv_length)
        elif side == "client":
            seq_bin = long_to_bytes(self.seq_client, iv_length)
        else:
            0/0
        return bytes(x1 ^ x2 for x1, x2 in zip(write_iv, seq_bin))

    def seq_upd_server(self):
        self.seq_server += 1

    def seq_upd_client(self):
        self.seq_client += 1

    @staticmethod
    def load_x509_cert(data_path: str):
        with open(data_path, "rb") as f:
            cert = f.read()
            cert = x509.load_pem_x509_certificate(cert)
        return cert

    @staticmethod
    def load_x509_key(data_path: str):
        with open(data_path, "rb") as f:
            private_key = f.read()
            private_key = load_pem_private_key(private_key, None)
        return private_key


def main():
    # お借りしました:
    # https://github.com/elliptic-shiho/tls13/blob/816fb6ee584965806ecbb9ecab249fd45e07c702/src/tls/crypto/cipher_suite.rs#L204-L219
    initial_secret = bytes.fromhex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")
    client_initial_secret = bytes.fromhex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
    actual = TLSKey.HKDF_Expand_Label(initial_secret, b"client in", b"", SHA256_HASH_LEN)
    assert actual == client_initial_secret


if __name__ == '__main__':
    main()
