

def pad(data: bytes, block_size: int) -> bytes:
    if len(data) % block_size == 0:
        return data
    pad_len = (block_size * (len(data) // block_size + 1)) - len(data)
    return data + int.to_bytes(pad_len, 1) * pad_len


if __name__ == '__main__':
    print(pad(b"1" * 28, 16))
