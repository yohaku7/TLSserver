


class Byte:
    def __init__(self, value: int) -> None:
        if value < 0 or 255 < value:
            raise ValueError("Byteは0~255の値を指定してください")
        self.value = value
