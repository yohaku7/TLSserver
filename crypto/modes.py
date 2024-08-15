from dataclasses import dataclass
from abc import ABCMeta, abstractmethod

from crypto.aes import AES128


@dataclass(frozen=True)
class AESMode(metaclass=ABCMeta):
    aes: AES128

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
class AuthenticatedAESMode(metaclass=ABCMeta):
    aes: AES128

    @abstractmethod
    def authenticated_encrypt(self, plaintext: bytes, authenticated_data: bytes) -> bytes:
        pass

    @abstractmethod
    def authenticated_decrypt(self, ciphertext: bytes, authenticated_data: bytes, tag: bytes) -> bytes:
        pass


@dataclass(frozen=True)
class AESModeWithIVAndAdditionalData(metaclass=ABCMeta):
    iv: bytes



@dataclass(frozen=True)
class ECB(AESMode):
    def encrypt(self, plaintext: bytes) -> bytes:
        assert len(plaintext) % 16 == 0
        blocks = []
        for i in range(0, len(plaintext), 16):
            blocks.append(plaintext[i: i + 16])
        enc = b""
        for block in blocks:
            enc += self.aes.cipher(block)
        return enc

    def decrypt(self, ciphertext: bytes) -> bytes:
        assert len(ciphertext) % 16 == 0
        blocks = []
        for i in range(0, len(ciphertext), 16):
            blocks.append(ciphertext[i: i + 16])
        dec = b""
        for block in blocks:
            dec += self.aes.inv_cipher(block)
        return dec
