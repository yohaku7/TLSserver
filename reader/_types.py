from typing import Literal


type _Base = Literal["raw", "bin", "dec", "hex", "int", "utf8"]
type _Unit = Literal["bit", "byte"]
type _DataKind = bytes | int | str


__all__ = [
    "_Base", "_Unit", "_DataKind"
]
