# AES Tests
# Refer: NIST FIPS197 (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
from ..aes import AESAlgorithm, SBox, AES128, AES192, AES256
from ..modes import ECB, CBC


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


# Refer: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core_All.pdf


def test_AES128_ECB():
    plaintext = bytes.fromhex("6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710")
    key = bytes.fromhex("2B7E1516 28AED2A6 ABF71588 09CF4F3C")
    ciphertext = bytes.fromhex("3AD77BB4 0D7A3660 A89ECAF3 2466EF97 F5D3D585 03B9699D E785895A 96FDBAAF 43B1CD7F 598ECE23 881B00E3 ED030688 7B0C785E 27E8AD3F 82232071 04725DD4")
    aes128 = AES128(key)
    ecb = ECB(aes128)
    assert ecb.encrypt(plaintext) == ciphertext
    assert ecb.decrypt(ciphertext) == plaintext


def test_AES192_ECB():
    plaintext = bytes.fromhex("6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710")
    key = bytes.fromhex("8E73B0F7 DA0E6452 C810F32B 809079E5 62F8EAD2 522C6B7B")
    ciphertext = bytes.fromhex("BD334F1D 6E45F25F F712A214 571FA5CC 97410484 6D0AD3AD 7734ECB3 ECEE4EEF EF7AFD22 70E2E60A DCE0BA2F ACE6444E 9A4B41BA 738D6C72 FB166916 03C18E0E")
    aes192 = AES192(key)
    ecb = ECB(aes192)
    assert ecb.encrypt(plaintext) == ciphertext
    assert ecb.decrypt(ciphertext) == plaintext


def test_AES256_ECB():
    plaintext = bytes.fromhex("6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710")
    key = bytes.fromhex("603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4")
    ciphertext = bytes.fromhex("F3EED1BD B5D2A03C 064B5A7E 3DB181F8 591CCB10 D410ED26 DC5BA74A 31362870 B6ED21B9 9CA6F4F9 F153E7B1 BEAFED1D 23304B7A 39F9F3FF 067D8D8F 9E24ECC7")
    aes256 = AES256(key)
    ecb = ECB(aes256)
    assert ecb.encrypt(plaintext) == ciphertext
    assert ecb.decrypt(ciphertext) == plaintext


def test_AES128_CBC():
    key = bytes.fromhex("2B7E1516 28AED2A6 ABF71588 09CF4F3C")
    iv = bytes.fromhex("00010203 04050607 08090A0B 0C0D0E0F")
    plaintext = bytes.fromhex("6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710")
    ciphertext = bytes.fromhex("7649ABAC 8119B246 CEE98E9B 12E9197D 5086CB9B 507219EE 95DB113A 917678B2 73BED6B8 E3C1743B 7116E69E 22229516 3FF1CAA1 681FAC09 120ECA30 7586E1A7")
    aes128 = AES128(key)
    cbc = CBC(aes128, iv)
    assert cbc.encrypt(plaintext) == ciphertext
    assert cbc.decrypt(ciphertext) == plaintext


def test_AES192_CBC():
    key = bytes.fromhex("8E73B0F7 DA0E6452 C810F32B 809079E5 62F8EAD2 522C6B7B")
    iv = bytes.fromhex("00010203 04050607 08090A0B 0C0D0E0F")
    plaintext = bytes.fromhex("6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710")
    ciphertext = bytes.fromhex("4F021DB2 43BC633D 7178183A 9FA071E8 B4D9ADA9 AD7DEDF4 E5E73876 3F69145A 571B2420 12FB7AE0 7FA9BAAC 3DF102E0 08B0E279 88598881 D920A9E6 4F5615CD")
    aes192 = AES192(key)
    cbc = CBC(aes192, iv)
    assert cbc.encrypt(plaintext) == ciphertext
    assert cbc.decrypt(ciphertext) == plaintext


def test_AES256_CBC():
    key = bytes.fromhex("603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4")
    iv = bytes.fromhex("00010203 04050607 08090A0B 0C0D0E0F")
    plaintext = bytes.fromhex("6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710")
    ciphertext = bytes.fromhex("F58C4C04 D6E5F1BA 779EABFB 5F7BFBD6 9CFC4E96 7EDB808D 679F777B C6702C7D 39F23369 A9D9BACF A530E263 04231461 B2EB05E2 C39BE9FC DA6C1907 8C6A9D1B")
    aes256 = AES256(key)
    cbc = CBC(aes256, iv)
    assert cbc.encrypt(plaintext) == ciphertext
    assert cbc.decrypt(ciphertext) == plaintext
