from __future__ import annotations

import copy
import math
import typing
from dataclasses import dataclass, field

from Crypto.Util.number import long_to_bytes


def make_int_array(length: int) -> list[int]:
    return [0 for _ in range(length)]


def BlockMul(X: int, Y: int):
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


def BlockPow(X: int, pow: int) -> int:
    res = 1
    t = X
    n = pow
    while n != 0:
        if n & 1 == 1:
            res = BlockMul(res, t)
        t = BlockMul(t, t)
        n >>= 1
    return res


def GHASH(subkey: bytes, X: bytes) -> bytes:
    assert len(X) % 16 == 0
    subkey = int.from_bytes(subkey)
    m = int.from_bytes(X).bit_length() // 128
    X_ = make_int_array(m)
    for i in range(0, len(X_), 16):
        X_[i] = int.from_bytes(X[i: i + 16])
    Y_ = make_int_array(m + 1)
    Y_[0] = 0
    for i in range(m):
        Y_[i + 1] = BlockMul(Y_[i] ^ X_[i], subkey)
    return long_to_bytes(Y_[m])


def GCTR(aes, icb: GCMCounter, X: bytes) -> bytes:
    if len(X) == 0:
        return b""
    n = math.ceil(int.from_bytes(X).bit_length() / 128)
    print(f"n = {n}")
    X_ = make_int_array(n)
    for i in range(0, len(X), 16):
        X_[i // 16] = int.from_bytes(X[i: i + 16])
    Y_ = make_int_array(n)
    CB = copy.deepcopy(icb)

    print(f"X0 = {X_[0]}, CB = {int.from_bytes(aes.cipher(CB.encode()))}")
    Y_[0] = X_[0] ^ int.from_bytes(aes.cipher(CB.encode()))
    CB.increment()

    for i in range(1, n - 1):
        print(f"Xi = {X_[i]}, CB = {int.from_bytes(aes.cipher(CB.encode()))}")
        Y_[i] = X_[i] ^ int.from_bytes(aes.cipher(CB.encode()))
        CB.increment()

    print(f"X[n] = {X_}")

    Y_[n - 1] = X_[n - 1] ^ int.from_bytes(aes.cipher(CB.encode())[:len(long_to_bytes(X_[n - 1]))])
    # Y_[n - 1] = X_[n - 1] ^ MSB(len(bin(X_[n - 1])[2:]), int.from_bytes(aes.cipher(CB_[n - 1].encode())))

    Y = ''.join([bin(y)[2:] for y in Y_])
    assert len(long_to_bytes(int(Y, 2))) == len(X)
    return long_to_bytes(int(Y, 2))


@dataclass
class GCMCounter:
    iv: bytes
    counter: int = 1

    def increment(self):
        self.counter = (self.counter + 1) % (2 ** 32)

    def incremented(self) -> GCMCounter:
        return GCMCounter(self.iv, (self.counter + 1) % (2 ** 32))

    def to_int(self) -> int:
        return int.from_bytes(self.encode())

    def encode(self) -> bytes:
        res = self.iv + int.to_bytes(self.counter, 4)
        assert len(res) == 16
        return res


@dataclass
class GCM:
    __counter: GCMCounter = field(init=False)
    iv: bytes

    tag_len: typing.ClassVar[int] = 16

    def __post_init__(self):
        assert 1 <= int.from_bytes(self.iv).bit_length() <= (2 ** 64) - 1
        self.__counter = GCMCounter(self.iv)

    def AuthenticatedEncrypt(self, aes, plaintext: bytes, authenticated_data: bytes) -> tuple[bytes, bytes]:
        # §7.1
        H = aes.cipher(b"\x00" * 16)
        print(f"H = {H.hex()}")
        assert int.from_bytes(self.iv).bit_length() <= 96  # TODO: 96ビット以外を対応
        J_0 = copy.deepcopy(self.__counter)
        # C = GCTR(aes, inc(32, J_0), plaintext)
        self.__counter.increment()
        C = GCTR(aes, self.__counter, plaintext)
        u = 128 * math.ceil(int.from_bytes(C).bit_length() / 128) - int.from_bytes(C).bit_length()
        v = (128 * math.ceil(int.from_bytes(authenticated_data).bit_length() / 128) -
             int.from_bytes(authenticated_data).bit_length())
        print(f"v = {v}, u = {u}")
        assert v % 8 == 0
        assert u % 8 == 0
        S = GHASH(H, authenticated_data +
                  b"\x00" * (v // 8) +
                  C +
                  b"\x00" * (u // 8) +
                  int.to_bytes(int.from_bytes(authenticated_data).bit_length(), 8) +
                  int.to_bytes(int.from_bytes(C).bit_length(), 8)
                  )
        print(f"S = {S.hex()}")
        print(f"counter = {J_0.counter}")
        T = GCTR(aes, J_0, S)
        return C, T


if __name__ == '__main__':
    assert BlockMul(0x697665206d65205def52aaf986cab595, 0x97e1f84eaa6cda96140c37276ad5f6fe) == 0x747c259415e7648615ea33bedb3f08e8
    x = 32368182074896728973496185888283307777
    assert BlockMul(x, x) == BlockPow(x, 2)
    assert BlockMul(x, BlockMul(x, x)) == BlockPow(x, 3)

    c = GCMCounter(b"\x70" * 12)
    print(c.encode())
    print(c.incremented().encode())
