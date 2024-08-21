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
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
    iv = bytes.fromhex("cafebabefacedbaddecaf888")
    A = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    P = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
    C, T = GCMAlgorithm.Encrypt(key, iv, A, P, 16)
    exp_C, exp_T = bytes.fromhex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"), bytes.fromhex("5bc94fbc3221a5db94fae95ae7121a47")
    assert C.hex() == exp_C.hex(), C.hex()
    assert T.hex() == exp_T.hex(), T.hex()


if __name__ == '__main__':
    TestCase2()
