# elliptic
from __future__ import annotations

import pprint
from dataclasses import dataclass
from abc import ABCMeta


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
        self.__param = ECParameter

    def __call__(self, *args, **kwargs):
        assert len(args) == 2
        x, y = args


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
        R = ECPoint.O
        T = self
        while other != 0:
            if other & 1 == 1:
                R = T + R
            T = T + T
            other = other >> 1
        return R

    def __repr__(self):
        return f"EC Point ({self.x}, {self.y})"


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


def main():
    pprint.pprint(secp256r1.G * 1337)


if __name__ == '__main__':
    main()
