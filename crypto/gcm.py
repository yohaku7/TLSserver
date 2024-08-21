from __future__ import annotations

from dataclasses import dataclass

from crypto.aes import AESAlgorithm
from crypto.padding import zero_pad


class GCMAlgorithm:
    @classmethod
    def BlockMul(cls, X: int, Y: int):
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
        return res

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
        print(f"H = {subkey.hex()}")
        X = 0
        A = zero_pad(authenticated_data, 16)
        C = zero_pad(ciphertext, 16)
        rev = lambda x: int(bin(x)[2:][::-1], 2)
        for i in range(0, len(A), 16):
            a = A[i: i + 16]
            X = cls.BlockMul(X ^ int.from_bytes(a), H)
            print(f"X, A[{i}: {i + 16}] = {hex(X)[2:]}, {a.hex()}")
        for i in range(0, len(C), 16):
            c = C[i: i + 16]
            X = cls.BlockMul(X ^ int.from_bytes(c), H)
            print(f"X, C[{i}: {i + 16}] = {hex(X)[2:]}, {c.hex()}")
        print(f"X_{{m+n}}: {X.to_bytes(16).hex()}")
        A_C_len = (len(authenticated_data) * 8).to_bytes(8) + (len(ciphertext) * 8).to_bytes(8)
        print(f"len(A)||len(C) = {A_C_len.hex()}")
        X = cls.BlockMul(X ^ int.from_bytes(A_C_len), H)
        return X

    @classmethod
    def Encrypt(cls, key: bytes, iv: bytes, authenticated_data: bytes, plaintext: bytes, tag_len: int) -> tuple[bytes, bytes]:
        H = AESAlgorithm.Cipher(int.to_bytes(0, 16), 10, key)
        rev = lambda x: int(bin(x)[2:][::-1], 2)
        H = int.to_bytes(rev(int.from_bytes(H)), 16)
        print(f"H: {H.hex()}")
        counter = GCMCounter.generate(H, iv)
        Y0 = counter.encode()
        print(f"Y0: {Y0.hex()}")
        C = b""
        for i in range(0, len(plaintext), 16):
            P = plaintext[i: i + 16]
            counter.increment()
            print(f"Y = {counter.encode().hex()}")
            E = AESAlgorithm.Cipher(counter.encode(), 10, key)
            print(f"E[{i}:{i + 16}] = {E.hex()}")
            Plen = len(P)
            E = int.from_bytes(E[:Plen])
            C += int.to_bytes(int.from_bytes(P) ^ E, 16)
        print(f"E[Y0] = {AESAlgorithm.Cipher(Y0, 10, key).hex()}")
        ghash = GCMAlgorithm.GHash(H, authenticated_data, C)
        print(f"GHASH(H, A, C) = {int.to_bytes(ghash, 16).hex()}")
        T = ghash ^ int.from_bytes(AESAlgorithm.Cipher(Y0, 10, key))
        T >>= 16 - tag_len
        print(f"T: {int.to_bytes(T, tag_len).hex()}")
        return C, int.to_bytes(T, tag_len)


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


def main():
    x = 0x0388dace60b6a392f328c2b971b2fe78
    y = 0x66e94bd4ef8a2c3b884cfa59ca342b2e
    exp = 108496359886984208562716007604011040540
    res = GCMAlgorithm.BlockMul(x, y)
    assert res == exp

    # print(GCMAlgorithm.GHash(bytes.fromhex("66e94bd4ef8a2c3b884cfa59ca342b2e"), b"", bytes.fromhex("0388dace60b6a392f328c2b971b2fe78")))

    (auth_data, ciphertext) = (bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
                               bytes.fromhex("42831ec2217774244b7221b784d0d49c e3aa212f2c02a4e035c17e2329aca12e 21d514b25466931c7d8f6a5aac84aa05 1ba30b396a0aac973d58e091 "))
    exp = 140308029854786508595581050281538465375
    subkey = bytes.fromhex("b83b533708bf535d0aa6e52980d53b78")
    print("GHASH =", GCMAlgorithm.GHash(subkey, auth_data, ciphertext))


if __name__ == '__main__':
    main()
