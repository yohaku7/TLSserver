# elliptic
from __future__ import annotations

import math
from dataclasses import dataclass, field
from abc import ABCMeta
import secrets
from Crypto.Util.number import long_to_bytes


@dataclass
class ECParameter(metaclass=ABCMeta):
    name: str
    p: int
    a: int
    b: int
    __Gx: int
    __Gy: int
    n: int
    h: int

    def __post_init__(self):
        self.G = ECPoint(self, self.__Gx, self.__Gy)
        self.order = self.n * self.h


class EC:
    def __init__(self, param: ECParameter):
        self.__param = param

    @property
    def param(self) -> ECParameter:
        return self.__param

    def __call__(self, *args, **kwargs):
        assert len(args) == 2
        x, y = args
        return ECPoint(self.__param, x, y)

    def random_point(self) -> ECPoint:
        while True:
            x = secrets.randbelow(self.__param.p)
            assert x != 0
            y = root_mod(x ** 3 + self.__param.a * x + self.__param.b, self.__param.p)
            if (y ** 2) % self.__param.p == (x ** 3 + self.__param.a * x + self.__param.b) % self.__param.p:
                return ECPoint(self.__param, x, y)


def legendre(a, p) -> int:
    assert p != 2
    if math.gcd(a, p) != 1:
        return 0
    res = pow(a, (p - 1) // 2, p)
    if p - res == 1:
        return -1
    else:
        return 1


def root_mod(a: int, p: int) -> int:
    if p % 8 in (3, 7):
        return pow(a, (p + 1) // 4, p)
    elif p % 8 == 5:
        res = pow(a, (p + 3) // 8, p)
        if res ** 2 != a:
            return (res * pow(2, (p - 1) // 4)) % p
        return res
    elif p % 8 == 1:
        Q = p - 1
        S = 0
        while Q % 2 == 0:
            Q //= 2
            S += 1
        z = 2
        while legendre(z, p) != -1:
            z += 1
            print(z)
        M = S
        c = pow(z, Q, p)
        t = pow(a, Q, p)
        R = pow(a, (Q + 1) // 2, p)
        while True:
            if t == 0:
                return 0
            elif t == 1:
                return R
            i = 1
            while pow(t, pow(2, i), p) != 1:
                i += 1
            assert 0 < i < M
            b = pow(c, pow(2, M - i - 1, p), p)
            M = i
            c = (b ** 2) % p
            t = (t * (b ** 2)) % p
            R = (R * b) % p


class ECPoint:
    O = None

    def __init__(self, param: ECParameter, x: int, y: int):
        self.__param = param
        self.__x = x
        self.__y = y

    @property
    def x(self) -> int:
        return self.__x

    @property
    def y(self) -> int:
        return self.__y

    def __eq__(self, other: ECPoint):
        if other == ECPoint.O:
            return False
        return self.x == other.x and self.y == other.y

    def __add__(self, other: ECPoint | str):
        if self == ECPoint.O:
            return other
        elif other == ECPoint.O:
            return self

        assert self.__param == other.__param

        if self.x == other.x and self.y == -other.y:
            return ECPoint.O
        if self == other:
            delta = ((3 * (self.x ** 2) + self.__param.a) * pow(2 * self.y, -1, self.__param.p)) % self.__param.p
        else:
            delta = ((other.y - self.y) * pow(other.x - self.x, -1, self.__param.p)) % self.__param.p
        x = ((delta ** 2) - self.x - other.x) % self.__param.p
        y = (delta * (self.x - x) - self.y) % self.__param.p
        return ECPoint(self.__param, x, y)

    def __mul__(self, other: int):
        # バイナリ法での実装
        R = ECPoint.O
        T = self
        while other != 0:
            if other & 1 == 1:
                R = T + R
            T = T + T
            other = other >> 1
        return R

    def __repr__(self):
        return f"ECPoint({self.x}, {self.y})"


secp256r1 = ECParameter(
    "secp256r1",
    0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
    0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
    0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    0x1
)


@dataclass(frozen=True)
class ECPrivateKey:
    key: int
    param: ECParameter

    def sign(self, message: bytes) -> ECSign:
        h = int.from_bytes(message) % self.param.n
        k = secrets.randbelow(self.param.n)
        assert 1 <= k <= self.param.n - 1
        r = (self.param.G * k).x % self.param.n
        s = ((h + self.key * r) * pow(k, -1, self.param.n)) % self.param.n
        return ECSign(r, s)


@dataclass(frozen=True)
class ECPublicKey:
    key: ECPoint
    param: ECParameter = field(repr=False)

    def verify(self, sign: ECSign, message: bytes) -> bool:
        u = (pow(sign.s, -1, self.param.n) * int.from_bytes(message)) % self.param.n
        v = (pow(sign.s, -1, self.param.n) * sign.r) % self.param.n
        print(self.param.G * u)
        return ((self.param.G * u) + (self.key * v)).x == sign.r


@dataclass(frozen=True)
class ECSign:
    r: int
    s: int

    def encode(self) -> bytes:
        return long_to_bytes(self.r) + long_to_bytes(self.s)


@dataclass(frozen=True)
class ECDSA:
    ec: EC

    def generate_key(self) -> tuple[ECPublicKey, ECPrivateKey]:
        a = secrets.randbelow(self.ec.param.p)
        A = self.ec.param.G * a
        return ECPublicKey(A, self.ec.param), ECPrivateKey(a, self.ec.param)


def main():
    E = EC(secp256r1)
    print(E.random_point())
    ecdsa = ECDSA(E)
    pub, key = ecdsa.generate_key()
    print(pub, key)
    s = key.sign(b"\xff\xff")
    print(s)
    print(pub.verify(s, b"\xff\xff"))


if __name__ == '__main__':
    print(root_mod(13, 17))
    main()
