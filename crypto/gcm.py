from __future__ import annotations

import copy
import math
import typing
from dataclasses import dataclass, field

from Crypto.Util.number import long_to_bytes


def to_bin_array(x: int, length: int) -> list[int]:
    return [int(b, 2) for b in format(x, f"0{length}b")]

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


# def LSB(s: int, X: int) -> int:
#     return X & ((1 << s) - 1)


def MSB(s: int, X: int) -> int:
    length = 128
    if s == length:
        return X
    assert length > s, f"{length} > {s}"
    mask = ((1 << length) - 1) ^ ((1 << (length - s)) - 1)
    masked = X & mask
    return masked >> (length - s)


# def inc(s: int, X: int) -> int:
#     Xbin = bin(X)[2:]
#     res = MSB(len(Xbin) - s, X) + format((LSB(s, X) + 1) % (2 ** s), f"0{s}b")
#     return int(res, 2)


def GHASH(subkey: bytes, X: bytes) -> int:
    assert len(X) % 16 == 0
    subkey = int.from_bytes(subkey)
    m = len(X) // 16
    X_ = make_int_array(m)
    for i in range(0, len(X_), 16):
        X_[i] = int.from_bytes(X[i: i + 16])
    Y_ = make_int_array(m + 1)
    Y_[0] = 0
    for i in range(1, m + 1):
        Y_[i] = BlockMul(Y_[i - 1] ^ X_[i - 1], subkey)
    return Y_[m]


def GCTR(aes, icb: GCMCounter, X: bytes) -> int:
    if len(X) == 0:
        return 0
    n = math.ceil(len(X) / 16)
    X_ = make_int_array(n)
    for i in range(0, len(X), 16):
        X_[i // 16] = int.from_bytes(X[i: i + 16])
    Y_ = [0 for _ in range(n)]
    CB_: list[GCMCounter | None] = [None for _ in range(n)]
    CB_[0] = icb
    for i in range(2, n + 1):
        CB_[i - 1] = CB_[i - 2].incremented()
        # CB_[i - 1] = inc(32, CB_[i - 2])
    print(f"cb: {CB_}")
    for i in range(1, n):
        Y_[i - 1] = X_[i - 1] ^ int.from_bytes(aes.cipher(CB_[i - 1].encode()))
    # Y_[n - 1] = X_[n - 1] ^ MSB(len(bin(X_[n - 1])[2:]), int.from_bytes(aes.cipher(CB_[n - 1].encode())))
    Y_[n - 1] = X_[n - 1] ^ int.from_bytes(aes.cipher(CB_[n - 1].encode())[:len(long_to_bytes(X_[n - 1]))])

    Y = ''.join([bin(y)[2:] for y in Y_])
    return int(Y, 2)


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
        assert 1 <= len(self.iv) * 8 <= (2 ** 64) - 1
        self.__counter = GCMCounter(self.iv)

    def AuthenticatedEncrypt(self, aes, plaintext: bytes, authenticated_data: bytes) -> tuple[bytes, bytes]:
        # §7.1
        H = aes.cipher(b"\x00" * 16)
        assert len(self.iv) == 12  # TODO: 12バイト以外を対応
        J_0 = copy.deepcopy(self.__counter)
        # C = GCTR(aes, inc(32, J_0), plaintext)
        self.__counter.increment()
        C = GCTR(aes, self.__counter, plaintext)
        u = 16 * math.ceil(len(long_to_bytes(C)) / 16) - len(long_to_bytes(C))
        v = 16 * math.ceil(len(authenticated_data) / 16) - len(authenticated_data)
        S = GHASH(H, authenticated_data +
                  b"\00" * v +
                  long_to_bytes(C) +
                  b"\x00" * u +
                  int.to_bytes(len(authenticated_data) * 8, 8) +
                  int.to_bytes(len(long_to_bytes(C)) * 8, 8))
        print(f"s: 128, ")
        print(J_0.counter)
        T = MSB(128, GCTR(aes, J_0, long_to_bytes(S)))
        return long_to_bytes(C), long_to_bytes(T)


if __name__ == '__main__':
    assert BlockMul(0x697665206d65205def52aaf986cab595, 0x97e1f84eaa6cda96140c37276ad5f6fe) == 0x747c259415e7648615ea33bedb3f08e8
    x = 32368182074896728973496185888283307777
    assert BlockMul(x, x) == BlockPow(x, 2)
    assert BlockMul(x, BlockMul(x, x)) == BlockPow(x, 3)

    c = GCMCounter(b"\x70" * 12)
    print(c.encode())
    print(c.incremented().encode())
