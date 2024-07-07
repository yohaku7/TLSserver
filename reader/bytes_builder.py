class BytesBuilder:
    def __init__(self):
        self.__byte: bytes = b""

    def append_int(self, i: int, length: int):
        self.__byte += i.to_bytes(length, "big")

    def append_str(self, s: str):
        self.__byte += s.encode()

    def append(self, b: bytes):
        self.__byte += b

    def append_variable_length(self, header_length: int, b: bytes):
        length = len(b)
        self.__byte += length.to_bytes(header_length, "big")
        self.__byte += b

    def to_bytes(self):
        return self.__byte
