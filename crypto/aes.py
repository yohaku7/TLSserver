# AES Encrypt / Decrypt
from __future__ import annotations

import copy
from dataclasses import dataclass, field

import crypto.gcm
from crypto import modes, padding
from Crypto.Cipher import AES


# 参照: NIST規格

@dataclass
class State:
    # Refer: §3.4 The State
    __state: list[list[int]] = field(init=False)

    def __post_init__(self):
        self.__state = [
            [0 for _ in range(4)] for _ in range(4)
        ]

    @classmethod
    def from_input_bytes(cls, data: bytes) -> State:
        # Refer: §3.4 Eq. 3.6
        assert len(data) == 16
        s = State()
        for r in range(4):
            for c in range(4):
                s[r, c] = data[r + 4 * c]
        return s

    def get_word(self, column: int) -> Word:
        return Word(
            [self[r, column] for r in range(4)]
        )

    def output_bytes(self) -> bytes:
        out = bytearray([0 for _ in range(16)])
        for r in range(4):
            for c in range(4):
                out[r + 4 * c] = self[r, c]
        return bytes(out)

    def __getitem__(self, item: tuple):
        assert len(item) == 2
        r, c = item
        return self.__state[r][c]

    def __setitem__(self, key: tuple, value):
        assert len(key) == 2
        r, c = key
        self.__state[r][c] = value

    def __repr__(self):
        res = ""
        for r in range(4):
            res += (f"| {self[r, 0].to_bytes().hex()} | {self[r, 1].to_bytes().hex()} | {self[r, 2].to_bytes().hex()} |"
                    f" {self[r, 3].to_bytes().hex()} |\n")
        return res


@dataclass
class Word:
    __bytes: list[int]

    def __post_init__(self):
        assert len(self.__bytes) == 4

    def hex(self) -> str:
        return bytes(self.__bytes).hex()

    def __getitem__(self, item: int):
        return self.__bytes[item]

    def __setitem__(self, key: int, value: int):
        self.__bytes[key] = value

    def __xor__(self, other: Word):
        res = [0, 0, 0, 0]
        for i in range(4):
            res[i] = self[i] ^ other[i]
        return Word(res)


# Refer: §4.5
def XTimes(b: int):
    b_7 = (b >> 7) & 1
    if b_7 == 0:
        return b << 1
    else:
        return (b << 1) ^ 0b100011011


def XTimesMul(a: int, b: int):
    res = 0
    t = b
    while t != 0:
        if t & 1 == 1:
            res ^= a
        a = XTimes(a)
        t >>= 1
    return res


def XTimesPow(a: int, pow: int) -> int:
    res = 1
    t = a
    n = pow
    while n != 0:
        if n & 1 == 1:
            res = XTimesMul(res, t)
        t = XTimesMul(t, t)
        n >>= 1
    return res


class SBox:
    __sBox: list[list[int]]
    __invSBox: list[list[int]]
    __generated: bool = False

    @classmethod
    def _generate(cls):
        sBox = [
            [0 for _ in range(16)] for _ in range(16)
        ]
        invSBox = [
            [0 for _ in range(16)] for _ in range(16)
        ]
        for x in range(0xf + 1):
            for y in range(0xf + 1):
                xy = (x << 4) | y
                s = cls._SBox(xy)
                sBox[x][y] = s
                s_x = (s & 0b11110000) >> 4
                s_y = s & 0b1111
                invSBox[s_x][s_y] = xy
        cls.__sBox = sBox
        cls.__invSBox = invSBox
        cls.__generated = True

    @classmethod
    def _SBox(cls, b: int) -> int:
        c = 0b01100011  # 固定ビット
        if b == 0:
            b_tilde = 0
        else:
            b_tilde = XTimesPow(b, 254)
        b_dash = [0 for _ in range(8)]
        for i in range(8):
            b_dash[i] = (((b_tilde >> i) & 1) ^ ((b_tilde >> ((i + 4) % 8)) & 1) ^ ((b_tilde >> ((i + 5) % 8)) & 1) ^
                         ((b_tilde >> ((i + 6) % 8)) & 1) ^ ((b_tilde >> ((i + 7) % 8)) & 1) ^ ((c >> i) & 1))
        return int("".join(map(str, reversed(b_dash))), 2)

    @classmethod
    def SBox(cls, b: int) -> int:
        if not cls.__generated:
            cls._generate()
        x = (b & 0b11110000) >> 4
        y = b & 0b1111
        return cls.__sBox[x][y]

    @classmethod
    def InvSBox(cls, b: int) -> int:
        if not cls.__generated:
            cls._generate()
        x = (b & 0b11110000) >> 4
        y = b & 0b1111
        return cls.__invSBox[x][y]


def SubBytes(state: State) -> State:
    # §5.1.1
    res = state
    for r in range(4):
        for c in range(4):
            res[r, c] = SBox.SBox(state[r, c])
    return res


def InvSubBytes(state: State) -> State:
    # §5.3.2
    res = state
    for r in range(4):
        for c in range(4):
            res[r, c] = SBox.InvSBox(state[r, c])
    return res


def ShiftRows(state: State) -> State:
    # §5.1.2
    res = copy.deepcopy(state)
    for r in range(4):
        for c in range(4):
            res[r, c] = state[r, (c + r) % 4]
    return res


def InvShiftRows(state: State) -> State:
    # §5.3.1
    res = copy.deepcopy(state)
    for r in range(4):
        for c in range(4):
            res[r, c] = state[r, (c - r) % 4]
    return res


def MixColumns(state: State) -> State:
    # §5.1.3
    a = Word([0x02, 0x01, 0x01, 0x03])
    res = copy.deepcopy(state)
    for c in range(4):
        res[0, c] = (XTimesMul(a[0], state[0, c]) ^ XTimesMul(a[3], state[1, c]) ^ XTimesMul(a[2], state[2, c]) ^
                     XTimesMul(a[1], state[3, c]))
        res[1, c] = (XTimesMul(a[1], state[0, c]) ^ XTimesMul(a[0], state[1, c]) ^ XTimesMul(a[3], state[2, c]) ^
                     XTimesMul(a[2], state[3, c]))
        res[2, c] = (XTimesMul(a[2], state[0, c]) ^ XTimesMul(a[1], state[1, c]) ^ XTimesMul(a[0], state[2, c]) ^
                     XTimesMul(a[3], state[3, c]))
        res[3, c] = (XTimesMul(a[3], state[0, c]) ^ XTimesMul(a[2], state[1, c]) ^ XTimesMul(a[1], state[2, c]) ^
                     XTimesMul(a[0], state[3, c]))
    return res


def InvMixColumns(state: State) -> State:
    # §5.3.3
    a = Word([0x0e, 0x09, 0x0d, 0x0b])
    res = copy.deepcopy(state)
    for c in range(4):
        res[0, c] = (XTimesMul(a[0], state[0, c]) ^ XTimesMul(a[3], state[1, c]) ^ XTimesMul(a[2], state[2, c]) ^
                     XTimesMul(a[1], state[3, c]))
        res[1, c] = (XTimesMul(a[1], state[0, c]) ^ XTimesMul(a[0], state[1, c]) ^ XTimesMul(a[3], state[2, c]) ^
                     XTimesMul(a[2], state[3, c]))
        res[2, c] = (XTimesMul(a[2], state[0, c]) ^ XTimesMul(a[1], state[1, c]) ^ XTimesMul(a[0], state[2, c]) ^
                     XTimesMul(a[3], state[3, c]))
        res[3, c] = (XTimesMul(a[3], state[0, c]) ^ XTimesMul(a[2], state[1, c]) ^ XTimesMul(a[1], state[2, c]) ^
                     XTimesMul(a[0], state[3, c]))
    return res


def AddRoundKey(state: State, round_keys: list[Word]) -> State:
    assert len(round_keys) == 4
    res = copy.deepcopy(state)
    for c in range(4):
        key = round_keys[c]
        res[0, c] = state[0, c] ^ key[0]
        res[1, c] = state[1, c] ^ key[1]
        res[2, c] = state[2, c] ^ key[2]
        res[3, c] = state[3, c] ^ key[3]
    return res


def RotWord(word: Word) -> Word:
    return Word([word[1], word[2], word[3], word[0]])


def SubWord(word: Word) -> Word:
    return Word([SBox.SBox(word[0]), SBox.SBox(word[1]), SBox.SBox(word[2]), SBox.SBox(word[3])])


def KeyExpansion(key: bytes) -> list[Word]:
    # §5.2 Alg. 2
    Rcon = [
        None,
        Word([0x01, 0x00, 0x00, 0x00]),
        Word([0x02, 0x00, 0x00, 0x00]),
        Word([0x04, 0x00, 0x00, 0x00]),
        Word([0x08, 0x00, 0x00, 0x00]),
        Word([0x10, 0x00, 0x00, 0x00]),
        Word([0x20, 0x00, 0x00, 0x00]),
        Word([0x40, 0x00, 0x00, 0x00]),
        Word([0x80, 0x00, 0x00, 0x00]),
        Word([0x1b, 0x00, 0x00, 0x00]),
        Word([0x36, 0x00, 0x00, 0x00])
    ]
    Nk, Nr = 4, 10
    i = 0
    w: list[Word | None] = [None for _ in range(4 * (Nr + 1))]
    while i <= Nk - 1:
        w[i] = Word(list(bytearray(key[4 * i : 4 * i + 4])))
        i += 1
    while i <= 4 * Nr + 3:
        temp = w[i - 1]
        if i % Nk == 0:
            temp = SubWord(RotWord(temp)) ^ Rcon[i // Nk]
        elif Nk > 6 and i % Nk == 4:
            temp = SubWord(temp)
        w[i] = w[i - Nk] ^ temp
        i += 1
    return w


# §5.1 Alg. 1
def Cipher(data: bytes, rounds: int, round_keys: list[Word]) -> bytes:
    assert len(data) == 16
    state = State.from_input_bytes(data)
    state = AddRoundKey(state, round_keys[:4])
    for r in range(1, rounds):
        state = SubBytes(state)
        state = ShiftRows(state)
        state = MixColumns(state)
        state = AddRoundKey(state, round_keys[4 * r: 4 * r + 4])
    state = SubBytes(state)
    state = ShiftRows(state)
    state = AddRoundKey(state, round_keys[4 * rounds: 4 * rounds + 4])
    return state.output_bytes()

# §5.3 Alg. 3
def InvCipher(ciphertext: bytes, rounds: int, round_keys: list[Word]) -> bytes:
    assert len(ciphertext) == 16
    state = State.from_input_bytes(ciphertext)
    state = AddRoundKey(state, round_keys[4 * rounds: 4 * rounds + 4])
    for r in range(rounds - 1, 0, -1):
        state = InvShiftRows(state)
        state = InvSubBytes(state)
        state = AddRoundKey(state, round_keys[4 * r: 4 * r + 4])
        state = InvMixColumns(state)
    state = InvShiftRows(state)
    state = InvSubBytes(state)
    state = AddRoundKey(state, round_keys[:4])
    return state.output_bytes()


class AES128:
    Rounds = 10
    KeyLength = 16

    def __init__(self, key: bytes):
        assert len(key) == AES128.KeyLength
        self.__key = key

    def cipher(self, data: bytes) -> bytes:
        return Cipher(data, AES128.Rounds, KeyExpansion(self.__key))

    def inv_cipher(self, ciphertext: bytes) -> bytes:
        return InvCipher(ciphertext, AES128.Rounds, KeyExpansion(self.__key))


def main():
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
        b = XTimes(b)
        assert b == e

    assert XTimesMul(0x57, 0x13) == 0xfe
    assert XTimesMul(0x53, 0x53) == XTimesPow(0x53, 2)

    assert SBox.SBox(0) == 0x63, f"{SBox.SBox(0)} == {0x63}"
    assert SBox.SBox(0x53) == 0xed, f"{SBox.SBox(0x53)} == {0xed}"
    assert SBox.InvSBox(SBox.SBox(0xed)) == 0xed

    plaintext = bytes.fromhex("6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51"
                              "30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710")
    key = bytes.fromhex("2B7E1516 28AED2A6 ABF71588 09CF4F3C")
    aes128 = AES128(key)
    ecb = modes.ECB(aes128)
    enc = ecb.encrypt(padding.pad(plaintext, 16))
    ciphertext = bytes.fromhex("3AD77BB4 0D7A3660 A89ECAF3 2466EF97 F5D3D585 03B9699D E785895A 96FDBAAF"
                               "43B1CD7F 598ECE23 881B00E3 ED030688 7B0C785E 27E8AD3F 82232071 04725DD4")
    assert enc == ciphertext
    dec = ecb.decrypt(enc)
    assert dec == plaintext

    A = b"Hello World"
    iv = b"\x20" * 12

    g = crypto.gcm.GCM(iv)
    enc, tag = g.AuthenticatedEncrypt(aes128, plaintext, A)
    print("e:", enc, "t:", tag)

    actual_aes128 = AES.new(key, AES.MODE_GCM, nonce=iv)
    actual_aes128.update(A)
    c, t = actual_aes128.encrypt_and_digest(plaintext)
    print(c, t)

    print(enc == c)


if __name__ == '__main__':
    main()
