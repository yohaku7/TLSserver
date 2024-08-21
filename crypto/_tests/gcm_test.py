from crypto.gcm import GCMAlgorithm


def test_TestCase1():
    key = int.to_bytes(0, 16)
    P = b""
    iv = int.to_bytes(0, 12)
    C, T = GCMAlgorithm.Encrypt(key, iv, b"", P, 16)
    exp_C, exp_T = b"", bytes.fromhex("58e2fccefa7e3061367f1d57a4e7455a")
    assert C == exp_C
    assert T == exp_T


def TestCase2():
    key = int.to_bytes(0, 16)
    P = int.to_bytes(0, 16)
    iv = int.to_bytes(0, 12)
    C, T = GCMAlgorithm.Encrypt(key, iv, b"", P, 16)
    exp_C, exp_T = bytes.fromhex("0388dace60b6a392f328c2b971b2fe78"), bytes.fromhex("ab6e47d42cec13bdf53a67b21257bddf")
    assert C.hex() == exp_C.hex()
    assert T.hex() == exp_T.hex()


if __name__ == '__main__':
    TestCase2()
