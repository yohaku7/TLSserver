import math
import secrets
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives.hmac import HMAC, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from common import ContentType, NamedGroup
from crypto import elliptic
from crypto.aes import AES128
from crypto.gcm import GCM
from Crypto.Util.number import long_to_bytes

from crypto.modes import CBC
from crypto.padding import pkcs7_pad
from crypto.x25519 import X25519, X25519PublicKey
from extension.key_share import KeyShareEntry
from handshake import ClientHello, Handshake, ServerHello
from reader import Block, Blocks, BytesReader

SHA256_HASH_LEN: int = 32


class SessionTicket:
    def __init__(self):
        self.key_id: int = 0

        with open("./temp/stek.key", mode="rb") as f:
            self.stek_master_key = f.read()
        self.stek_iv = secrets.token_bytes(16)
        self.stek_master_key = SessionTicket.HKDF_Extract(long_to_bytes(0, SHA256_HASH_LEN), self.stek_master_key)

        self.stek_key = SessionTicket.HKDF_Expand(self.stek_master_key, b"stek psk enc", 16)
        self.hmac_key = SessionTicket.HKDF_Expand(self.stek_master_key, b"stek hmac", SHA256_HASH_LEN)

        self.cbc = CBC(AES128(self.stek_key), self.stek_iv)

    # ticket の構造を下図に示す。
    # +------------------+---------------+--------------------------+
    # |                  |               |                          |
    # | Key ID (4 bytes) | IV (16 bytes) | Ticket Age Add (4 bytes) |
    # |                  |               |                          |
    # +------------------+---+-----------+----------+---------------+
    # |                      |    Encrypted PSK     |               |
    # | PSK Length (1 byte)  |          +           | MAC (SHA-256) |
    # |                      |       Padding        |               |
    # +----------------------+----------------------+---------------+
    def create_ticket(self, ticket_age_add: int, psk: bytes) -> bytes:
        ticket = b""
        ticket += long_to_bytes(self.key_id, 4)
        ticket += self.stek_iv
        plaintext = long_to_bytes(ticket_age_add, 4) + long_to_bytes(len(psk), 1) + psk
        plaintext = pkcs7_pad(plaintext, 16)
        ciphertext = self.cbc.encrypt(plaintext)
        ciphertext_len = len(ciphertext)
        ticket += long_to_bytes(ciphertext_len, 2)
        ticket += ciphertext
        mac = SessionTicket.HMAC(self.hmac_key, ticket)
        ticket += mac
        self.key_id += 1
        return ticket

    def verify_ticket(self, ticket: bytes) -> bool:
        fragment = ticket[:-SHA256_HASH_LEN]
        real_mac = ticket[-SHA256_HASH_LEN:]
        mac = SessionTicket.HMAC(self.hmac_key, fragment)
        return mac == real_mac

    def decrypt_ticket(self, ticket: bytes) -> tuple[bytes, int]:
        assert self.verify_ticket(ticket)
        br = BytesReader(ticket[:-SHA256_HASH_LEN])
        key_id, iv, encrypted = Blocks([
            Block(4, "raw"),
            Block(16, "raw"),
            Block(2, "raw", variable=True),
        ]).parse(br)
        plaintext = self.cbc.decrypt(encrypted)
        br = BytesReader(plaintext)
        ticket_age_add, psk = Blocks([
            Block(4, "int"),
            Block(1, "raw", variable=True),
        ]).parse(br)
        return psk, ticket_age_add

    @staticmethod
    def HMAC(key: bytes, data: bytes):
        hmac = HMAC(key, hashes.SHA256())
        hmac.update(data)
        return hmac.finalize()

    @staticmethod
    def HKDF_Extract(salt: bytes, ikm: bytes) -> bytes:
        # RFC5869 §2.2
        return SessionTicket.HMAC(salt, ikm)

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


class HKDF:
    def __init__(self, salt: bytes, ikm: bytes):
        self.salt: bytes = salt
        self.ikm: bytes = ikm

    @staticmethod
    def HMAC(key: bytes, data: bytes):
        hmac = HMAC(key, hashes.SHA256())
        hmac.update(data)
        return hmac.finalize()

    @staticmethod
    def HKDF_Extract(salt: bytes, ikm: bytes) -> bytes:
        # RFC5869 §2.2
        return HKDF.HMAC(salt, ikm)

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
        return HKDF.HKDF_Expand(secret, hkdf_label, length)


class TLSConnectionKey:
    def __init__(self):
        self.__transcript_hash = hashes.Hash(hashes.SHA256())

        self.x25519_shared_key: bytes | None = None
        self.x25519: X25519 | None = None
        self.binder_key: bytes | None = None
        self.client_early_traffic_secret: bytes | None = None
        self.early_exporter_master_secret: bytes | None = None
        self.client_handshake_traffic_secret: bytes | None = None
        self.server_handshake_traffic_secret: bytes | None = None

        self.client_application_seq: int = 0
        self.server_application_seq: int = 0
        self.client_handshake_seq: int = 0
        self.server_handshake_seq: int = 0

        self.__secret_state: bytes | None = None

        self.master_secret: bytes | None = None
        self.client_application_traffic_secret: list[bytes] = []
        self.server_application_traffic_secret: list[bytes] = []
        self.exporter_master_secret: bytes | None = None
        self.resumption_master_secret: bytes | None = None

        self.ecdsa_cert: elliptic.ECPublicKey | None = None
        self.ecdsa_key: elliptic.ECPrivateKey | None = None

        self.psk: bytes | None = None

    def exchange_key_x25519(self, entry: KeyShareEntry):
        assert entry.group == NamedGroup.x25519
        client_x25519_public_key = X25519PublicKey.from_bytes(entry.key_exchange)
        self.x25519 = X25519()
        self.x25519_shared_key = self.x25519.exchange(client_x25519_public_key)

    def update_transcript_hash(self, new_hash: bytes):
        self.__transcript_hash.update(new_hash)

    @property
    def current_transcript_hash(self):
        # RFC8446 §4.4.1
        sha256 = self.__transcript_hash.copy()
        return sha256.finalize()

    def Derive_Secret(self, secret: bytes, label: bytes):
        t_hash = self.current_transcript_hash
        return HKDF.HKDF_Expand_Label(secret, label, t_hash, SHA256_HASH_LEN)

    def _calc_nonce(self, write_iv: bytes, seq: int):
        # RFC8446 §5.3, RFC5116 §5.1
        iv_length = 12  # RFC5116 §5.1
        seq_bin = long_to_bytes(seq, iv_length)
        return bytes(x1 ^ x2 for x1, x2 in zip(write_iv, seq_bin))

    def derive_early_secrets(self, psk: bytes | None):
        psk = self.psk if self.psk is not None else psk
        if psk is None:
            psk = long_to_bytes(0, SHA256_HASH_LEN)
        else:
            assert len(psk) == SHA256_HASH_LEN

        early_secret = HKDF.HKDF_Extract(long_to_bytes(0, SHA256_HASH_LEN), psk)
        self.binder_key = self.Derive_Secret(early_secret, b"res binder")
        self.client_early_traffic_secret = self.Derive_Secret(early_secret, b"c e traffic")
        self.early_exporter_master_secret = self.Derive_Secret(early_secret, b"e exp master")

        self.__secret_state = self.Derive_Secret(early_secret, b"derived")

    def derive_handshake_secrets(self):
        assert self.x25519_shared_key is not None

        handshake_secret = HKDF.HKDF_Extract(self.__secret_state, self.x25519_shared_key)
        self.client_handshake_traffic_secret = self.Derive_Secret(handshake_secret, b"c hs traffic")
        self.server_handshake_traffic_secret = self.Derive_Secret(handshake_secret, b"s hs traffic")

        self.__secret_state = self.Derive_Secret(handshake_secret, b"derived")

    def encrypt_with_handshake_secret(self, data: bytes, additional_data: bytes, sender: Literal["server", "client"]):
        """
        [sender]_handshake_traffic_secret を用い、RFC 8446 に則って data を暗号化する。
        :param data: 暗号化するバイト列。
        :param additional_data: AES-GCM の additional_data。
        :param sender: 暗号鍵の [sender] の部分。
        :return: 暗号文。
        """
        # RFC5116 §5.1
        secret = self.server_handshake_traffic_secret if sender == "server" else self.client_handshake_traffic_secret
        assert secret is not None

        write_key = HKDF.HKDF_Expand_Label(secret, b"key", b"", 16)
        write_iv = HKDF.HKDF_Expand_Label(secret, b"iv", b"", 12)

        nonce = self._calc_nonce(write_iv, self.server_handshake_seq)
        gcm = GCM(AES128(write_key), nonce)
        encrypted = gcm.encrypt(additional_data, data, 16)

        if sender == "server":
            self.server_handshake_seq += 1
        else:
            self.client_handshake_seq += 1

        return encrypted

    def decrypt_with_handshake_secret(self, data: bytes, additional_data: bytes, sender: Literal["server", "client"]):
        """
        [sender]_handshake_traffic_secret を用い、RFC 8446 に則って TLSCiphertext を復号する。
        :param data: 暗号文。
        :param additional_data: AES-GCM の additional_data。
        :param sender: 暗号鍵の [sender] の部分。
        :return: (平文, 認証に成功したか) のタプル。認証に失敗した場合、平文の中身は未定義。
        """
        tag = data[-16:]
        ciphertext = data[:-16]

        # RFC5116 §5.1
        secret = self.server_handshake_traffic_secret if sender == "server" else self.client_handshake_traffic_secret
        assert secret is not None

        write_key = HKDF.HKDF_Expand_Label(secret, b"key", b"", 16)
        write_iv = HKDF.HKDF_Expand_Label(secret, b"iv", b"", 12)

        nonce = self._calc_nonce(write_iv, self.server_handshake_seq)
        gcm = GCM(AES128(write_key), nonce)
        decrypted, valid = gcm.decrypt(additional_data, ciphertext, tag)

        if valid:
            if sender == "server":
                self.server_handshake_seq += 1
            else:
                self.client_handshake_seq += 1

        return decrypted, valid

class TLSKey:
    def __init__(self):
        self.x25519_shared_key: bytes | None = None
        self.x25519: X25519 | None = None
        self.binder_key: bytes | None = None
        self.client_early_traffic_secret: bytes | None = None
        self.early_exporter_master_secret: bytes | None = None
        self.client_handshake_traffic_secret: bytes | None = None
        self.server_handshake_traffic_secret: bytes | None = None

        self.client_application_seq: int = 0
        self.server_application_seq: int = 0
        self.client_handshake_seq: int = 0
        self.server_handshake_seq: int = 0

        self.__secret_state: bytes | None = None

        self.master_secret: bytes | None = None
        self.client_application_traffic_secret: list[bytes] = []
        self.server_application_traffic_secret: list[bytes] = []
        self.exporter_master_secret: bytes | None = None
        self.resumption_master_secret: bytes | None = None

        self.ecdsa_cert: elliptic.ECPublicKey | None = None
        self.ecdsa_key: elliptic.ECPrivateKey | None = None

        self.psk: bytes | None = None

    def exchange_key_x25519(self, entry: KeyShareEntry):
        assert entry.group == NamedGroup.x25519
        client_x25519_public_key = X25519PublicKey.from_bytes(entry.key_exchange)
        self.x25519 = X25519()
        self.x25519_shared_key = self.x25519.exchange(client_x25519_public_key)

    def derive_secrets(self, psk: bytes | None, ch: ClientHello, sh: ServerHello):
        psk = self.psk if self.psk is not None else psk
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
            raw += Handshake.unparse(hs)
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
        additional_data = (
            long_to_bytes(opaque_type) +
            long_to_bytes(legacy_record_version) +
             long_to_bytes(length, 2)  # RFC8446 §5.2
        )
        nonce = self._calc_nonce(write_iv, self.server_handshake_seq)
        gcm = GCM(AES128(write_key), nonce)
        encrypted = gcm.encrypt(additional_data, data, 16)
        self.server_handshake_seq += 1
        return encrypted

    def decrypt_handshake(self, data: bytes, opaque_type: ContentType, legacy_record_version: int, length: int) -> tuple[bytes, bool]:
        tag = data[-16:]
        real_data = data[:-16]
        assert self.client_handshake_traffic_secret is not None
        write_key = TLSKey.HKDF_Expand_Label(self.client_handshake_traffic_secret, b"key", b"", 16)
        write_iv = TLSKey.HKDF_Expand_Label(self.client_handshake_traffic_secret, b"iv", b"", 12)
        additional_data = (
            long_to_bytes(opaque_type) +
            long_to_bytes(legacy_record_version) +
            long_to_bytes(length, 2)  # RFC8446 §5.2
        )
        nonce = self._calc_nonce(write_iv, self.client_handshake_seq)
        gcm = GCM(AES128(write_key), nonce)
        decrypted, valid = gcm.decrypt(additional_data, real_data, tag)
        if valid:
            self.client_handshake_seq += 1
        return decrypted, valid

    def encrypt_application_data(self, data: bytes, opaque_type: ContentType, legacy_record_version: int, length: int):
        assert self.server_application_traffic_secret[0] is not None
        write_key = TLSKey.HKDF_Expand_Label(self.server_application_traffic_secret[0], b"key", b"", 16)
        write_iv = TLSKey.HKDF_Expand_Label(self.server_application_traffic_secret[0], b"iv", b"", 12)
        additional_data = (
            long_to_bytes(opaque_type) +
            long_to_bytes(legacy_record_version) +
            long_to_bytes(length, 2)  # RFC8446 §5.2
        )
        nonce = self._calc_nonce(write_iv, self.server_application_seq)
        gcm = GCM(AES128(write_key), nonce)
        encrypted = gcm.encrypt(additional_data, data, 16)
        self.server_application_seq += 1
        return encrypted

    def decrypt_application_data(self, data: bytes, opaque_type: ContentType, legacy_record_version: int, length: int):
        tag = data[-16:]
        real_data = data[:-16]
        assert self.client_application_traffic_secret[0] is not None
        write_key = TLSKey.HKDF_Expand_Label(self.client_application_traffic_secret[0], b"key", b"", 16)
        write_iv = TLSKey.HKDF_Expand_Label(self.client_application_traffic_secret[0], b"iv", b"", 12)
        additional_data = (
            long_to_bytes(opaque_type) +
            long_to_bytes(legacy_record_version) +
            long_to_bytes(length, 2)  # RFC8446 §5.2
        )
        nonce = self._calc_nonce(write_iv, self.client_application_seq)
        gcm = GCM(AES128(write_key), nonce)
        decrypted, valid = gcm.decrypt(additional_data, real_data, tag)
        if valid:
            self.client_application_seq += 1
        return decrypted, valid

    def decrypt_early_data(self, data: bytes):
        tag = data[-16:]
        real_data = data[:-16]
        assert self.client_early_traffic_secret is not None
        write_key = TLSKey.HKDF_Expand_Label(self.client_early_traffic_secret, b"key", b"", 16)
        write_iv = TLSKey.HKDF_Expand_Label(self.client_early_traffic_secret, b"iv", b"", 12)
        additional_data = (
            long_to_bytes(ContentType.application_data) +
            long_to_bytes(0x0303) +
            long_to_bytes(len(data), 2)  # RFC8446 §5.2
        )
        nonce = self._calc_nonce(write_iv, 0)
        gcm = GCM(AES128(write_key), nonce)
        decrypted, valid = gcm.decrypt(additional_data, real_data, tag)
        return decrypted, valid

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

    def make_psk(self, ticket_nonce: bytes) -> bytes:
        assert self.resumption_master_secret is not None
        return TLSKey.HKDF_Expand_Label(self.resumption_master_secret, b"resumption", ticket_nonce, SHA256_HASH_LEN)

    def set_psk(self, psk: bytes):
        self.psk = psk

    def _calc_nonce(self, write_iv: bytes, seq: int):
        # RFC8446 §5.3, RFC5116 §5.1
        iv_length = 12  # RFC5116 §5.1
        seq_bin = long_to_bytes(seq, iv_length)
        return bytes(x1 ^ x2 for x1, x2 in zip(write_iv, seq_bin))

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
