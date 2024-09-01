from __future__ import annotations


class GF:
    def __init__(self, p: int):
        self.__p = p

    def add(self, a: int, b: int) -> int:
        return (a + b) % self.__p

    def sub(self, a: int, b: int) -> int:
        return (a - b) % self.__p

    def mul(self, a: int, b: int) -> int:
        return (a * b) % self.__p

    def div(self, a: int, b: int) -> int:
        return self.mul(a, pow(b, -1, self.__p))

    def pow(self, a: int, exp: int) -> int:
        return pow(a, exp, self.__p)
