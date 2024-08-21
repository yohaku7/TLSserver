from crypto.aes import AES128, AES192
from crypto.gcm import GCM

# Refer: https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
# Appendix B.


def run_aes128_test(key: bytes, iv: bytes,
                    plaintext: bytes, ciphertext: bytes,
                    authenticated_data: bytes, tag: bytes):
    gcm = GCM(AES128(key), iv)
    c, t = gcm.encrypt(authenticated_data, plaintext, 16)
    assert c == ciphertext
    assert t == tag
    p = gcm.decrypt(authenticated_data, ciphertext, tag)
    assert p == plaintext


def run_aes192_test(key: bytes, iv: bytes,
                    plaintext: bytes, ciphertext: bytes,
                    authenticated_data: bytes, tag: bytes):
    gcm = GCM(AES192(key), iv)
    c, t = gcm.encrypt(authenticated_data, plaintext, 16)
    assert c == ciphertext
    assert t == tag
    p = gcm.decrypt(authenticated_data, ciphertext, tag)
    assert p == plaintext


def test_TestCase1():
    run_aes128_test(
        int.to_bytes(0, 16), int.to_bytes(0, 12),
        b"", b"",
        b"", bytes.fromhex("58e2fccefa7e3061367f1d57a4e7455a")
    )


def test_TestCase2():
    run_aes128_test(
        int.to_bytes(0, 16), int.to_bytes(0, 12),
        int.to_bytes(0, 16), bytes.fromhex("0388dace60b6a392f328c2b971b2fe78"),
        b"", bytes.fromhex("ab6e47d42cec13bdf53a67b21257bddf")
    )


def test_TestCase3():
    run_aes128_test(
        bytes.fromhex("feffe9928665731c6d6a8f9467308308"),
        bytes.fromhex("cafebabefacedbaddecaf888"),
        bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"),
        bytes.fromhex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"),
        b"",
        bytes.fromhex("4d5c2af327cd64a62cf35abd2ba6fab4")
    )


def test_TestCase4():
    run_aes128_test(
        bytes.fromhex("feffe9928665731c6d6a8f9467308308"),
        bytes.fromhex("cafebabefacedbaddecaf888"),
        bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
        bytes.fromhex(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"),
        bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        bytes.fromhex("5bc94fbc3221a5db94fae95ae7121a47")
    )


def test_TestCase5():
    run_aes128_test(
        bytes.fromhex("feffe9928665731c6d6a8f9467308308"),
        bytes.fromhex("cafebabefacedbad"),
        bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
        bytes.fromhex(
            "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598"),
        bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        bytes.fromhex("3612d2e79e3b0785561be14aaca2fccb")
    )


def test_TestCase6():
    run_aes128_test(
        bytes.fromhex("feffe9928665731c6d6a8f9467308308"),
        bytes.fromhex(
            "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b"),
        bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
        bytes.fromhex(
            "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5"),
        bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        bytes.fromhex("619cc5aefffe0bfa462af43c1699d050")
    )


def test_TestCase7():
    run_aes192_test(
        int.to_bytes(0, 24), int.to_bytes(0, 12),
        b"", b"",
        b"", bytes.fromhex("cd33b28ac773f74ba00ed1f312572435")
    )


def test_TestCase8():
    run_aes192_test(
        int.to_bytes(0, 24), int.to_bytes(0, 12),
        int.to_bytes(0, 16), bytes.fromhex("98e7247c07f0fe411c267e4384b0f600"),
        b"", bytes.fromhex("2ff58d80033927ab8ef4d4587514f0fb")
    )


def test_TestCase9():
    run_aes192_test(
        bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c"),
        bytes.fromhex("cafebabefacedbaddecaf888"),
        bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"),
        bytes.fromhex(
            "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256"),
        b"",
        bytes.fromhex("9924a7c8587336bfb118024db8674a14")
    )


def test_TestCase10():
    run_aes192_test(
        bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c"),
        bytes.fromhex("cafebabefacedbaddecaf888"),
        bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
        bytes.fromhex(
            "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710"),
        bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        bytes.fromhex("2519498e80f1478f37ba55bd6d27618c")
    )


def test_TestCase11():
    run_aes192_test(
        bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c"),
        bytes.fromhex("cafebabefacedbad"),
        bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
        bytes.fromhex(
            "0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7"),
        bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        bytes.fromhex("65dcc57fcf623a24094fcca40d3533f8")
    )


def test_TestCase12():
    run_aes192_test(
        bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c"),
        bytes.fromhex("9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b"),
        bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
        bytes.fromhex(
            "d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b"),
        bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        bytes.fromhex("dcf566ff291c25bbb8568fc3d376a6d9")
    )
