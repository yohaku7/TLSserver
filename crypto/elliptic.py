# EC (Elliptic Cipher)
from __future__ import annotations
import abc, math, secrets
import typing
from dataclasses import dataclass, field

from Crypto.Util.number import long_to_bytes

from crypto import asn1


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
    a %= p
    if p % 8 in (3, 7):
        return pow(a, (p + 1) // 4, p)
    elif p % 8 == 5:
        res = pow(a, (p + 3) // 8, p)
        if res ** 2 != a:
            return (res * pow(2, (p - 1) // 4, p)) % p
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
    # Q = p - 1
    # S = 0
    # while Q % 2 == 0:
    #     Q //= 2
    #     S += 1
    # z = 2
    # while legendre(z, p) != -1:
    #     z += 1
    # M = S
    # c = pow(z, Q, p)
    # t = pow(a, Q, p)
    # R = pow(a, (Q + 1) // 2, p)
    # while True:
    #     if t == 0:
    #         return 0
    #     elif t == 1:
    #         return R
    #     i = 1
    #     while pow(t, pow(2, i), p) != 1:
    #         i += 1
    #     assert 0 < i < M
    #     b = pow(c, pow(2, M - i - 1, p), p)
    #     M = i
    #     c = (b ** 2) % p
    #     t = (t * (b ** 2)) % p
    #     R = (R * b) % p


@dataclass(frozen=True)
class ECPoint(metaclass=abc.ABCMeta):
    Origin: typing.ClassVar[str] = "Origin Point"
    x: int
    y: int

    def __eq__(self, other: ECPoint) -> bool:
        if other == ECPoint.Origin:
            return False
        return self.x == other.x and self.y == other.y


@dataclass(frozen=True)
class EllipticCurve(metaclass=abc.ABCMeta):
    mod: int
    a: int
    b: int
    G: ECPoint
    order: int = field(kw_only=True)
    cofactor: int = field(kw_only=True)

    @abc.abstractmethod
    def _coordinate_on_curve(self, x: int, y: int) -> bool:
        pass

    @abc.abstractmethod
    def on_curve(self, point: ECPoint) -> bool:
        pass

    @abc.abstractmethod
    def random_point(self):
        pass

    @abc.abstractmethod
    def add(self, P: ECPoint, Q: ECPoint) -> ECPoint:
        pass

    @typing.final
    def mul(self, P: ECPoint, other: int) -> ECPoint:
        # バイナリ法での実装
        R = ECPoint.Origin
        T = P
        while other != 0:
            if other & 1 == 1:
                R = self.add(T, R)
            T = self.add(T, T)
            other >>= 1
        return R

    @typing.final
    def encode_point(self, point: ECPoint) -> bytes:
        # SEC 1 v2.0 §2.3.3, §2.3.5, §2.3.7
        if point == ECPoint.Origin:
            return b"\x00"
        # 点の圧縮は行われていないものと仮定する。
        mlen = math.ceil(math.log2(self.order) / 8)
        # 有限体の位数の最大の素因数は、奇素数と仮定する。
        # §2.3.7 のとおりに変換する。
        assert 2 ** (8 * mlen) > point.x
        # xを基数256で展開する
        x = point.x
        xl = [0 for _ in range(mlen)]
        for i in range(1, mlen + 1):
            factor = 2 ** (8 * (mlen - i))
            while x >= factor:
                x -= factor
                xl[mlen - i] += 1
        assert x == 0
        X = b""
        for i in range(mlen):
            X += int.to_bytes(xl[mlen - 1 - i])
        assert 2 ** (8 * mlen) > point.x
        # yを基数256で展開する
        y = point.y
        yl = [0 for _ in range(mlen)]
        for i in range(1, mlen + 1):
            factor = 2 ** (8 * (mlen - i))
            while y >= factor:
                y -= factor
                yl[mlen - i] += 1
        assert y == 0
        Y = b""
        for i in range(mlen):
            Y += int.to_bytes(xl[mlen - 1 - i])
        return b"\x04" + X + Y


@dataclass(frozen=True)
class WeierstrassCurve(EllipticCurve):
    def __post_init__(self):
        assert self.on_curve(self.G)

    def _coordinate_on_curve(self, x: int, y: int) -> bool:
        return pow(y, 2, self.mod) == (x ** 3 + self.a * x + self.b) % self.mod

    def on_curve(self, point: ECPoint) -> bool:
        return self._coordinate_on_curve(point.x, point.y)

    def random_point(self) -> ECPoint:
        while True:
            x = secrets.randbelow(self.mod)
            assert x != 0
            y = root_mod(x ** 3 + self.a * x + self.b, self.mod)
            if self._coordinate_on_curve(x, y):
                return ECPoint(x, y)

    def add(self, P: ECPoint, Q: ECPoint) -> ECPoint:
        if P == ECPoint.Origin:
            return Q
        elif Q == ECPoint.Origin:
            return P
        if P.x == Q.x and P.y == -Q.y:
            return ECPoint.Origin

        if P == Q:
            delta = ((3 * (P.x ** 2) + self.a) * pow(2 * P.y, -1, self.mod)) % self.mod
        else:
            delta = ((Q.y - P.y) * pow(Q.x - P.x, -1, self.mod)) % self.mod
        x = ((delta ** 2) - P.x - Q.x) % self.mod
        y = (delta * (P.x - x) - P.y) % self.mod
        return ECPoint(x, y)


@dataclass(frozen=True)
class MontgomeryCurve(EllipticCurve):
    def _coordinate_on_curve(self, x: int, y: int) -> bool:
        return (self.b * (y ** 2)) % self.mod == (x ** 3 + self.a * (x ** 2) + x) % self.mod

    def on_curve(self, point: ECPoint) -> bool:
        return self._coordinate_on_curve(point.x, point.y)

    def random_point(self):
        while True:
            x = secrets.randbelow(self.mod)
            assert x != 0
            y = root_mod(x ** 3 + self.a * (x ** 2) + x, self.mod)
            if self._coordinate_on_curve(x, y):
                return ECPoint(x, y)

    def from_xCoordinate(self, x: int):
        assert x != 0
        y = root_mod(x ** 3 + self.a * (x ** 2) + x, self.mod)
        if self._coordinate_on_curve(x, y):
            return ECPoint(x, y)
        else:
            raise ValueError(f"x-coordinate {x} does not exist on this curve.")

    def add(self, P: ECPoint, Q: ECPoint) -> ECPoint:
        if P == ECPoint.Origin:
            return Q
        elif Q == ECPoint.Origin:
            return P
        if P.x == Q.x and P.y == -Q.y:
            return ECPoint.Origin

        if P == Q:
            delta = ((3 * (P.x ** 2) + 2 * self.a * P.x + 1) * pow(2 * self.b * P.y, -1, self.mod)) % self.mod
        else:
            delta = ((Q.y - P.y) * pow(Q.x - P.x, -1, self.mod)) % self.mod
        intercept = (P.y - delta * P.x) % self.mod
        x = (self.b * pow(delta, 2, self.mod)) - self.a - P.x - Q.x
        x %= self.mod
        y = -(delta * x + intercept) % self.mod
        return ECPoint(x, y)

    def mul_montgomery_ladder(self, x: int, scalar: int) -> int:
        # https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Constant_time_Montgomery_ladder
        x1, x2, z2, x3, z3 = x, 1, 0, x, 1
        swap = 0
        for i in reversed(range(255)):
            bit = (scalar >> i) & 1
            swap ^= bit
            x2, x3 = self._c_swap(swap, x2, x3)
            z2, z3 = self._c_swap(swap, z2, z3)
            swap = bit

            A = (x2 + z2) % self.mod
            AA = pow(A, 2, self.mod)
            B = (x2 - z2) % self.mod
            BB = pow(B, 2, self.mod)
            E = (AA - BB) % self.mod
            C = (x3 + z3) % self.mod
            D = (x3 - z3) % self.mod
            DA = (D * A) % self.mod
            CB = (C * B) % self.mod
            x3 = pow(DA + CB, 2, self.mod)
            z3 = (x1 * pow(DA - CB, 2, self.mod)) % self.mod
            x2 = (AA * BB) % self.mod
            a24 = (self.a - 2) // 4
            z2 = (E * (AA + a24 * E)) % self.mod
        return (x2 * pow(z2, self.mod - 2, self.mod)) % self.mod

    @classmethod
    def _c_swap(cls, swap, a, b) -> (int, int):
        dummy = (0 - swap) & (a ^ b)
        a ^= dummy
        b ^= dummy
        return a, b


# Supported Curves Definitions
secp256r1 = WeierstrassCurve(
    0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
    0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    ECPoint(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
            0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
    order=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    cofactor=0x01
)
Curve25519 = MontgomeryCurve(
    0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed,
    0x76d06,
    0x01,
    ECPoint(0x09, 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9),
    order=0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed,
    cofactor=0x08
)


# RFC5915
@dataclass(frozen=True)
class ECPrivateKey:
    key: int
    param: EllipticCurve

    @classmethod
    def from_private_bytes(cls, private_key: bytes, param: EllipticCurve) -> ECPrivateKey:
        return cls(int.from_bytes(private_key), param)

    @property
    def digest(self) -> bytes:
        return long_to_bytes(self.key)

    def public_key(self) -> ECPublicKey:
        return ECPublicKey(self.param.mul(self.param.G, self.key), self.param)
        # return ECPublicKey(self.param.G * self.key, self.param)

    def sign(self, message: bytes) -> ECSign:
        h = int.from_bytes(message) % self.param.order
        k = secrets.randbelow(self.param.order)
        assert 1 <= k <= self.param.order - 1
        r = self.param.mul(self.param.G, k).x % self.param.order
        # r = (self.param.G * k).x % self.param.order
        s = ((h + self.key * r) * pow(k, -1, self.param.order)) % self.param.order
        return ECSign(r, s)


@dataclass(frozen=True)
class ECPublicKey:
    key: ECPoint
    param: EllipticCurve = field(repr=False)

    def verify(self, sign: ECSign, message: bytes) -> bool:
        u = (pow(sign.s, -1, self.param.order) * int.from_bytes(message)) % self.param.order
        v = (pow(sign.s, -1, self.param.order) * sign.r) % self.param.order
        return self.param.add(self.param.mul(self.param.G, u), self.param.mul(self.key, v)).x == sign.r
        # return ((self.param.G * u) + (self.key * v)).x == sign.r


@dataclass(frozen=True)
class ECSign:
    r: int
    s: int

    def encode(self) -> bytes:
        return asn1.Sequence.encode([
            asn1.Integer(self.r),
            asn1.Integer(self.s),
        ])


@dataclass(frozen=True)
class ECDSA:
    ec: EllipticCurve

    def generate_key(self) -> tuple[ECPublicKey, ECPrivateKey]:
        a = secrets.randbelow(self.ec.mod)
        A = self.ec.mul(self.ec.G, a)
        # A = self.ec.G * a
        return ECPublicKey(A, self.ec), ECPrivateKey(a, self.ec)


def main():
    G = Curve25519.G
    assert Curve25519.from_xCoordinate(0x9) == Curve25519.G
    Na = 0x111
    Nb = 0xfff
    Ka = Curve25519.mul(G, Na)
    Kb = Curve25519.mul(G, Nb)
    Sa = Curve25519.mul(Kb, Na)
    Sb = Curve25519.mul(Ka, Nb)
    assert Sa == Sb

    ecdsa = ECDSA(secp256r1)
    pub, key = ecdsa.generate_key()
    s = key.sign(b"\xff\xff")
    assert pub.verify(s, b"\xff\xff")


if __name__ == '__main__':
    main()
