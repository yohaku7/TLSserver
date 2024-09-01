from __future__ import annotations

from dataclasses import dataclass
import secrets
from .elliptic import Curve25519


class X25519:
    def __init__(self, *, secret_bytes: bytes = None, multiple_bytes: bytes = None):
        secret_bytes = secrets.token_bytes(32) if not secret_bytes else secret_bytes

        multiple = Curve25519.G.x if not multiple_bytes else X25519Util.decode_xCoordinate(multiple_bytes)
        scalar = X25519Util.decode_scalar(secret_bytes)
        self.__public_key = X25519PublicKey(Curve25519.mul_montgomery_ladder(multiple, scalar))
        self.__private_key = scalar

    @property
    def public_key(self) -> X25519PublicKey:
        return self.__public_key

    @property
    def private_key(self) -> int:
        return self.__private_key

    def exchange(self, public_key: X25519PublicKey) -> bytes:
        shared = Curve25519.mul_montgomery_ladder(public_key.xCoordinate, self.__private_key)
        return X25519Util.encode_xCoordinate(shared)


@dataclass(frozen=True)
class X25519PublicKey:
    xCoordinate: int

    @classmethod
    def from_bytes(cls, public_key: bytes) -> X25519PublicKey:
        return cls(X25519Util.decode_xCoordinate(public_key))

    def encode(self) -> bytes:
        return X25519Util.encode_xCoordinate(self.xCoordinate)


class X25519Util:
    @classmethod
    def encode_xCoordinate(cls, x: int) -> bytes:
        x %= Curve25519.mod
        return int.to_bytes(x, 32, "little")

    @classmethod
    def decode_xCoordinate(cls, x: bytes) -> int:
        assert len(x) == 32
        xl = bytearray(x)
        # 最後のバイトの最上位ビットをマスクする
        xl[-1] &= 0b01111111
        # 255bitの整数値の中で、GF(2^255-19)にないものは、剰余を取る。
        return int.from_bytes(xl, "little")

    @classmethod
    def decode_scalar(cls, k: bytes) -> int:
        assert len(k) == 32
        kl = bytearray(k)
        # 最初のバイトの最下位3ビットと、最後のバイトの最上位ビットを0に設定し、最後のバイトの2番目の上位ビットを1に設定し、リトルエンディアンとしてデコードする。
        kl[0] &= 0b11111000
        kl[31] &= 0b01111111
        kl[31] |= 0b01000000
        return int.from_bytes(kl, "little")


def main():
    a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    A = X25519(secret_bytes=a)
    assert A.public_key.encode().hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    b = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    B = X25519(secret_bytes=b)
    assert B.public_key.encode().hex() == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    KA = A.exchange(B.public_key)
    KB = B.exchange(A.public_key)
    assert KA == KB
    assert KA.hex() == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

    k = bytes.fromhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
    x = bytes.fromhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
    x25519 = X25519(secret_bytes=k, multiple_bytes=x)
    print(x25519.public_key.encode().hex())
    assert x25519.public_key.encode().hex() == "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"

    scalar = bytes.fromhex("0900000000000000000000000000000000000000000000000000000000000000")
    x = bytes.fromhex("0900000000000000000000000000000000000000000000000000000000000000")
    for i in range(1000):
        x25519 = X25519(secret_bytes=scalar, multiple_bytes=x)
        if i == 0:
            assert x25519.public_key.encode().hex() == "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
        x = scalar
        scalar = x25519.public_key.encode()
    assert x25519.public_key.encode().hex() == "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"


if __name__ == '__main__':
    main()
