from dataclasses import dataclass
from abc import ABCMeta, abstractmethod

from crypto.aes import AES

# Refer: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf


def bytes_xor(a: bytes, b: bytes) -> bytes:
    return bytes([a_e ^ b_e for a_e, b_e in zip(a, b, strict=True)])


@dataclass(frozen=True)
class AESMode(metaclass=ABCMeta):
    aes: AES

    @abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        pass


@dataclass(frozen=True)
class AESModeWithIV(AESMode, metaclass=ABCMeta):
    iv: bytes


@dataclass(frozen=True)
class AESModeWithIVAndAuthenticatedData(metaclass=ABCMeta):
    aes: AES
    iv: bytes

    @abstractmethod
    def encrypt(self, authenticated_data: bytes, plaintext: bytes, tag_len: int) -> tuple[bytes, bytes]:
        pass

    @abstractmethod
    def decrypt(self, authenticated_data: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        pass



@dataclass(frozen=True)
class ECB(AESMode):
    def encrypt(self, plaintext: bytes) -> bytes:
        assert len(plaintext) % 16 == 0
        enc = b""
        for i in range(0, len(plaintext), 16):
            block = plaintext[i: i + 16]
            enc += self.aes.encrypt(block)
        return enc

    def decrypt(self, ciphertext: bytes) -> bytes:
        assert len(ciphertext) % 16 == 0
        dec = b""
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i: i + 16]
            dec += self.aes.decrypt(block)
        return dec


@dataclass(frozen=True)
class CBC(AESModeWithIV):
    def encrypt(self, plaintext: bytes) -> bytes:
        assert len(self.iv) == 16
        assert len(plaintext) % 16 == 0
        enc = b""
        prev_enc = self.iv
        for i in range(0, len(plaintext), 16):
            block = plaintext[i: i + 16]
            prev_enc = self.aes.encrypt(bytes_xor(block, prev_enc))
            enc += prev_enc
        return enc

    def decrypt(self, ciphertext: bytes) -> bytes:
        assert len(self.iv) == 16
        assert len(ciphertext) % 16 == 0
        dec = b""
        prev_block = self.iv
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i: i + 16]
            prev_dec = bytes_xor(self.aes.decrypt(block), prev_block)
            prev_block = block
            dec += prev_dec
        return dec
