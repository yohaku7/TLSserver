from __future__ import annotations

from dataclasses import dataclass

from crypto.modes import AESModeWithIVAndAuthenticatedData
from crypto.padding import zero_pad


class GCMAlgorithm:
    @classmethod
    def BlockMul(cls, X: int, Y: int):
        rev = lambda x: int(format(x, "0128b")[::-1], 2)
        X = rev(X)
        Y = rev(Y)
        def _BlockXTimes(x: int) -> int:
            # 規格書ではリトルエンディアンだが、ビッグエンディアンで計算する
            R = (1 << 128) | 0b10000111
            b_127 = (x >> 127) & 1
            if b_127 == 0:
                return x << 1
            else:
                return (x << 1) ^ R

        assert _BlockXTimes(0x80000000000000000000000000000000) == 0x87

        res = 0
        V = Y
        while V != 0:
            if V & 1 == 1:
                res ^= X
            X = _BlockXTimes(X)
            V >>= 1
        return rev(res)

    @classmethod
    def BlockPow(cls, X: int, exp: int) -> int:
        res = 1
        t = X
        n = exp
        while n != 0:
            if n & 1 == 1:
                res = cls.BlockMul(res, t)
            t = cls.BlockMul(t, t)
            n >>= 1
        return res

    @classmethod
    def GHash(cls, subkey: bytes, authenticated_data: bytes, ciphertext: bytes) -> int:
        H = int.from_bytes(subkey)
        X = 0
        A = zero_pad(authenticated_data, 16)
        C = zero_pad(ciphertext, 16)
        for i in range(0, len(A), 16):
            a = A[i: i + 16]
            X = cls.BlockMul(X ^ int.from_bytes(a), H)
        for i in range(0, len(C), 16):
            c = C[i: i + 16]
            X = cls.BlockMul(X ^ int.from_bytes(c), H)
        A_C_len = (len(authenticated_data) * 8).to_bytes(8) + (len(ciphertext) * 8).to_bytes(8)
        X = cls.BlockMul(X ^ int.from_bytes(A_C_len), H)
        return X


@dataclass
class GCMCounter:
    iv: bytes
    count: int

    @classmethod
    def generate(cls, subkey: bytes, iv: bytes):
        if len(iv) == 12:
            return GCMCounter(iv, 1)
        else:
            value = GCMAlgorithm.GHash(subkey, b"", iv)
            count = value & ((1 << 32) - 1)
            return GCMCounter(int.to_bytes(value >> 32, 12), count)

    def encode(self) -> bytes:
        res = self.iv + int.to_bytes(self.count, 4)
        assert len(res) == 16
        return res

    def increment(self) -> None:
        self.count = (self.count + 1) % (2 ** 32)


@dataclass(frozen=True)
class GCM(AESModeWithIVAndAuthenticatedData):
    def encrypt(self, authenticated_data: bytes, plaintext: bytes, tag_len: int) -> tuple[bytes, bytes]:
        H = self.aes.encrypt(int.to_bytes(0, 16))
        H = int.to_bytes(int.from_bytes(H), 16)
        counter = GCMCounter.generate(H, self.iv)
        Y0 = counter.encode()
        C = b""
        for i in range(0, len(plaintext), 16):
            P = plaintext[i: i + 16]
            counter.increment()
            E = self.aes.encrypt(counter.encode())
            P_len = len(P)
            E = int.from_bytes(E[:P_len])
            C += int.to_bytes(int.from_bytes(P) ^ E, P_len)
        T = GCMAlgorithm.GHash(H, authenticated_data, C) ^ int.from_bytes(self.aes.encrypt(Y0))
        T >>= 16 - tag_len
        return C, int.to_bytes(T, tag_len)

    def decrypt(self, authenticated_data: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        H = self.aes.encrypt(int.to_bytes(0, 16))
        H = int.to_bytes(int.from_bytes(H), 16)
        counter = GCMCounter.generate(H, self.iv)
        Y0 = counter.encode()
        actual_tag = GCMAlgorithm.GHash(H, authenticated_data, ciphertext) ^ int.from_bytes(self.aes.encrypt(Y0))
        if int.from_bytes(tag) != actual_tag:
            raise ValueError("Invalid tag")
        P = b""
        for i in range(0, len(ciphertext), 16):
            C = ciphertext[i: i + 16]
            counter.increment()
            E = self.aes.encrypt(counter.encode())
            C_len = len(C)
            E = int.from_bytes(E[:C_len])
            P += int.to_bytes(int.from_bytes(C) ^ E, C_len)
        return P
