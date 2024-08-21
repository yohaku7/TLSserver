# AES Encrypt / Decrypt
from __future__ import annotations

import copy
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass, field


# 参照: NIST FIPS197 (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)

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


# FIX: なんかボトルネックになりそう
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

    def __repr__(self):
        return bytes(self.__bytes).hex()


class AESAlgorithm:
    @classmethod
    def xTimes(cls, x: int) -> int:
        # §4.5
        x_7 = (x >> 7) & 1
        if x_7 == 0:
            return x << 1
        else:
            return (x << 1) ^ 0b100011011

    @classmethod
    def xTimesMul(cls, x: int, y: int) -> int:
        res = 0
        a = x
        t = y
        while t != 0:
            if t & 1 == 1:
                res ^= a
            a = cls.xTimes(a)
            t >>= 1
        return res

    @classmethod
    def xTimesPow(cls, x: int, exp: int) -> int:
        res = 1
        t = x
        n = exp
        while n != 0:
            if n & 1 == 1:
                res = cls.xTimesMul(res, t)
            t = cls.xTimesMul(t, t)
            n >>= 1
        return res

    @classmethod
    def SBox(cls, x: int) -> int:
        return SBox.SBox(x)

    @classmethod
    def InvSBox(cls, x: int) -> int:
        return SBox.InvSBox(x)

    @classmethod
    def SubBytes(cls, state: State) -> State:
        # §5.1.1
        res = state
        for r in range(4):
            for c in range(4):
                res[r, c] = SBox.SBox(state[r, c])
        return res

    @classmethod
    def InvSubBytes(cls, state: State) -> State:
        # §5.3.2
        res = state
        for r in range(4):
            for c in range(4):
                res[r, c] = SBox.InvSBox(state[r, c])
        return res

    @classmethod
    def ShiftRows(cls, state: State) -> State:
        # §5.1.2
        res = copy.deepcopy(state)
        for r in range(4):
            for c in range(4):
                res[r, c] = state[r, (c + r) % 4]
        return res

    @classmethod
    def InvShiftRows(cls, state: State) -> State:
        # §5.3.1
        res = copy.deepcopy(state)
        for r in range(4):
            for c in range(4):
                res[r, c] = state[r, (c - r) % 4]
        return res

    @classmethod
    def MixColumns(cls, state: State) -> State:
        # §5.1.3
        a = Word([0x02, 0x01, 0x01, 0x03])
        res = copy.deepcopy(state)
        for c in range(4):
            res[0, c] = (cls.xTimesMul(a[0], state[0, c]) ^ cls.xTimesMul(a[3], state[1, c]) ^ cls.xTimesMul(a[2], state[2, c]) ^
                         cls.xTimesMul(a[1], state[3, c]))
            res[1, c] = (cls.xTimesMul(a[1], state[0, c]) ^ cls.xTimesMul(a[0], state[1, c]) ^ cls.xTimesMul(a[3], state[2, c]) ^
                         cls.xTimesMul(a[2], state[3, c]))
            res[2, c] = (cls.xTimesMul(a[2], state[0, c]) ^ cls.xTimesMul(a[1], state[1, c]) ^ cls.xTimesMul(a[0], state[2, c]) ^
                         cls.xTimesMul(a[3], state[3, c]))
            res[3, c] = (cls.xTimesMul(a[3], state[0, c]) ^ cls.xTimesMul(a[2], state[1, c]) ^ cls.xTimesMul(a[1], state[2, c]) ^
                         cls.xTimesMul(a[0], state[3, c]))
        return res

    @classmethod
    def InvMixColumns(cls, state: State) -> State:
        # §5.3.3
        a = Word([0x0e, 0x09, 0x0d, 0x0b])
        res = copy.deepcopy(state)
        for c in range(4):
            res[0, c] = (cls.xTimesMul(a[0], state[0, c]) ^ cls.xTimesMul(a[3], state[1, c]) ^ cls.xTimesMul(a[2], state[2, c]) ^
                         cls.xTimesMul(a[1], state[3, c]))
            res[1, c] = (cls.xTimesMul(a[1], state[0, c]) ^ cls.xTimesMul(a[0], state[1, c]) ^ cls.xTimesMul(a[3], state[2, c]) ^
                         cls.xTimesMul(a[2], state[3, c]))
            res[2, c] = (cls.xTimesMul(a[2], state[0, c]) ^ cls.xTimesMul(a[1], state[1, c]) ^ cls.xTimesMul(a[0], state[2, c]) ^
                         cls.xTimesMul(a[3], state[3, c]))
            res[3, c] = (cls.xTimesMul(a[3], state[0, c]) ^ cls.xTimesMul(a[2], state[1, c]) ^ cls.xTimesMul(a[1], state[2, c]) ^
                         cls.xTimesMul(a[0], state[3, c]))
        return res

    @classmethod
    def AddRoundKey(cls, state: State, round_keys: list[Word]) -> State:
        assert len(round_keys) == 4
        res = copy.deepcopy(state)
        for c in range(4):
            key = round_keys[c]
            res[0, c] = state[0, c] ^ key[0]
            res[1, c] = state[1, c] ^ key[1]
            res[2, c] = state[2, c] ^ key[2]
            res[3, c] = state[3, c] ^ key[3]
        return res

    @classmethod
    def KeyExpansion(cls, key: bytes, round_number: int) -> list[Word]:
        # §5.2 Alg. 2
        def RotWord(word: Word) -> Word:
            return Word([word[1], word[2], word[3], word[0]])

        def SubWord(word: Word) -> Word:
            return Word([SBox.SBox(word[0]), SBox.SBox(word[1]), SBox.SBox(word[2]), SBox.SBox(word[3])])

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
        assert len(key) % 8 == 0
        Nk, Nr = len(key) // 4, round_number
        i = 0
        w: list[Word | None] = [None for _ in range(4 * (Nr + 1))]
        while i <= Nk - 1:
            w[i] = Word(list(key[4 * i: 4 * i + 4]))
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

    @classmethod
    def Cipher(cls, data: bytes, round_number: int, key: bytes) -> bytes:
        # §5.1 Alg. 1
        assert len(data) == 16
        round_keys = cls.KeyExpansion(key, round_number)
        state = State.from_input_bytes(data)
        state = cls.AddRoundKey(state, round_keys[:4])
        for r in range(1, round_number):
            state = cls.SubBytes(state)
            state = cls.ShiftRows(state)
            state = cls.MixColumns(state)
            state = cls.AddRoundKey(state, round_keys[4 * r: 4 * r + 4])
        state = cls.SubBytes(state)
        state = cls.ShiftRows(state)
        state = cls.AddRoundKey(state, round_keys[4 * round_number: 4 * round_number + 4])
        return state.output_bytes()

    @classmethod
    def InvCipher(cls, data: bytes, round_number: int, key: bytes) -> bytes:
        # §5.3 Alg. 3
        assert len(data) == 16
        round_keys = cls.KeyExpansion(key, round_number)
        state = State.from_input_bytes(data)
        state = cls.AddRoundKey(state, round_keys[4 * round_number: 4 * round_number + 4])
        for r in range(round_number - 1, 0, -1):
            state = cls.InvShiftRows(state)
            state = cls.InvSubBytes(state)
            state = cls.AddRoundKey(state, round_keys[4 * r: 4 * r + 4])
            state = cls.InvMixColumns(state)
        state = cls.InvShiftRows(state)
        state = cls.InvSubBytes(state)
        state = cls.AddRoundKey(state, round_keys[:4])
        return state.output_bytes()


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
            b_tilde = AESAlgorithm.xTimesPow(b, 254)
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


@dataclass(frozen=True)
class AES(metaclass=ABCMeta):
    key: bytes

    @abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        pass


@dataclass(frozen=True)
class AES128(AES):
    def encrypt(self, plaintext: bytes) -> bytes:
        assert len(self.key) == 16
        return AESAlgorithm.Cipher(plaintext, 10, self.key)

    def decrypt(self, ciphertext: bytes) -> bytes:
        assert len(self.key) == 16
        return AESAlgorithm.InvCipher(ciphertext, 10, self.key)


@dataclass(frozen=True)
class AES192(AES):
    def encrypt(self, plaintext: bytes) -> bytes:
        assert len(self.key) == 24
        return AESAlgorithm.Cipher(plaintext, 12, self.key)

    def decrypt(self, ciphertext: bytes) -> bytes:
        assert len(self.key) == 24
        return AESAlgorithm.InvCipher(ciphertext, 12, self.key)


@dataclass(frozen=True)
class AES256(AES):
    def encrypt(self, plaintext: bytes) -> bytes:
        assert len(self.key) == 32
        return AESAlgorithm.Cipher(plaintext, 14, self.key)

    def decrypt(self, ciphertext: bytes) -> bytes:
        assert len(self.key) == 32
        return AESAlgorithm.InvCipher(ciphertext, 14, self.key)
