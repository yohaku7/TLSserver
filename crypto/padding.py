def pad(data: bytes, block_size: int) -> bytes:
    if len(data) % block_size == 0:
        return data
    pad_len = (block_size * (len(data) // block_size + 1)) - len(data)
    return data + int.to_bytes(pad_len, 1) * pad_len


def str_zero_pad(data: str, block_size: int, *, left: bool = False, right: bool = False) -> str:
    if len(data) % block_size == 0:
        return data
    pad_len = (block_size * (len(data) // block_size + 1)) - len(data)
    if left:
        return "0" * pad_len + data
    elif right:
        return data + "0" * pad_len
    else:
        raise ValueError("どちらの方向に埋めるかを指定してください。")


def zero_pad(data: bytes, block_size: int) -> bytes:
    if len(data) % block_size == 0:
        return data
    pad_len = (block_size * (len(data) // block_size + 1)) - len(data)
    return data + b"\x00" * pad_len


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    if len(data) % block_size == 0:
        return data + bytes([block_size] * block_size)
    pad_len = (block_size * (len(data) // block_size + 1)) - len(data)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

if __name__ == '__main__':
    print(zero_pad(b"1" * 28, 16))
    print(pkcs7_pad(b"1" * 30, 16))
    print(pkcs7_pad(b"1" * 32, 16))
    print(pkcs7_unpad(pkcs7_pad(b"1" * 30, 16), 16))
