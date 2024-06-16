# -*- coding: UTF-8 -*-
# written by yohaku7
from __future__ import annotations

from enum import Enum, auto


__all__ = [
    "IPv4Addr", "IPv4AddrClass",
    "IPv4_LOOPBACK_ADDRESS"
]


class IPv4AddrClass(Enum):
    """IPv4の利用用途によるクラス。"""
    A = auto()
    B = auto()
    C = auto()
    D = auto()
    E = auto()


class IPv4Addr:
    """IPv4。"""
    def __init__(self, octet1: int, octet2: int, octet3: int, octet4: int) -> None:
        if any([o < 0 or 255 < o for o in [octet1, octet2, octet3, octet4]]):
            raise ValueError("各オクテットの値は[0, 255]でなければなりません。")
        self.__octets = [octet1, octet2, octet3, octet4]

    @property
    def octets(self) -> list[int]:
        """IPアドレスの各オクテット。"""
        return self.__octets

    @property
    def ip_class(self) -> IPv4AddrClass:
        """IPv4のクラス。"""
        if self.octets[0] <= 127:
            return IPv4AddrClass.A
        elif 128 <= self.octets[0] <= 191:
            return IPv4AddrClass.B
        elif 192 <= self.octets[0] <= 223:
            return IPv4AddrClass.C
        elif 224 <= self.octets[0] <= 239:
            return IPv4AddrClass.D
        elif 240 <= self.octets[0]:
            return IPv4AddrClass.E


IPv4_LOOPBACK_ADDRESS = IPv4Addr(127, 0, 0, 1)


if __name__ == "__main__":
    i = IPv4Addr(192, 168, 3, 14)
    print(f"class: {i.ip_class}, octets: {i.octets}")
