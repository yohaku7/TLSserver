from dataclasses import dataclass
from Crypto.Util.number import long_to_bytes


@dataclass(frozen=True)
class ECDSASigValue:
    r: int
    s: int

    def encode(self):
        encoded = b""
        encoded += b"\x02"  # integer
        r_raw = long_to_bytes(self.r)
        encoded += long_to_bytes(len(r_raw)) + r_raw
        encoded += b"\x02"
        s_raw = long_to_bytes(self.s)
        encoded += long_to_bytes(len(s_raw)) + s_raw
        return encoded


if __name__ == '__main__':
    print(ECDSASigValue(111, 111).encode())
