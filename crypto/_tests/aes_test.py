# AES Tests
# Refer: NIST FIPS197 (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
from ..aes import AESAlgorithm, SBox


def test_xTimes():
    # §4.2
    b = 0x57
    expected = [
        0xae,
        0x47,
        0x8e,
        0x07,
        0x0e,
        0x1c,
        0x38
    ]
    for e in expected:
        b = AESAlgorithm.xTimes(b)
        assert b == e


def test_xTimesMul():
    # §4.2
    assert AESAlgorithm.xTimesMul(0x57, 0x13) == 0xfe


def test_xTimesPow():
    # xTimesMul(t, t) == xTimesPow(t, 2) であることを確認する
    # §4.2
    assert AESAlgorithm.xTimesMul(0x53, 0x53) == AESAlgorithm.xTimesPow(0x53, 2)


def test_SBox():
    # §5.1.1 Table 4.
    assert SBox.SBox(0) == 0x63
    assert SBox.SBox(0x53) == 0xed
    assert SBox.SBox(0x71) == 0xa3


def test_InvSBox():
    # §5.3.2 Table 6.
    assert SBox.InvSBox(0x63) == 0
    assert SBox.InvSBox(0xed) == 0x53
    assert SBox.InvSBox(0xa3) == 0x71


def test_Cipher():
    # Appendix B
    plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    expected_enc = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
    assert AESAlgorithm.Cipher(plaintext, 10, key) == expected_enc


def test_InvCipher():
    # Appendix B
    enc = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    expected_plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    assert AESAlgorithm.InvCipher(enc, 10, key) == expected_plaintext
