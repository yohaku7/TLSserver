# ASN.1 Encoder / Decoder
from Crypto.Util.number import long_to_bytes


class BitString:
    tag = b"\x03"

    def __init__(self, data: bytes):
        self.data = data

    def encode(self) -> bytes:
        """
        N ビットのビット列は N/8バイト(切り上げ) としてエンコードされますが、ビット数が8の倍数でない場合を明確にするために、
        「未使用ビット数」を表す1バイトのプレフィックスが付きます。
        例えば、ビット列011011100101110111(18ビット) をエンコードする場合、少なくとも3バイトが必要です。
        しかし、それは合計24ビットの容量があり必要とされる容量以上です。 それらのビットのうち6ビットは未使用です。
        それらの6ビットはビット列の右端に書き込まれるため、次のようにエンコードされます。

        ここでは、bytesを受け取るのでオクテット単位ということを前提にする。
        """
        prefix = b"\x00"
        return BitString.tag + prefix + self.data


class Integer:
    tag = b"\x02"

    def __init__(self, value: int):
        self.value = value

    def encode(self) -> bytes:
        encoded = long_to_bytes(self.value)
        if (encoded[0] & 0x80) >> 7 == 1:
            return Integer.tag + int.to_bytes(len(encoded) + 1, 1) + b"\x00" + encoded
        else:
            return Integer.tag + int.to_bytes(len(encoded), 1) + encoded


class Sequence:
    tag = b"\x30"

    @staticmethod
    def encode(objs: list) -> bytes:
        encoded = b""
        for obj in objs:
            encoded += obj.encode()
        return Sequence.tag + int.to_bytes(len(encoded), 1) + encoded
