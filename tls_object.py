from abc import abstractmethod, ABC
from exceptions import ParseError


class TLSObject(ABC):
    @classmethod
    @abstractmethod
    def parse(cls, data: bytes):
        """
        バイト列からパースしたオブジェクトを返す。
        :param data: パースするバイト列
        :return: パース後のオブジェクト
        """

    @abstractmethod
    def unparse(self, obj) -> bytes:
        """
        オブジェクトを、RFCの記法によりバイト列にする。
        :param obj: オブジェクト
        :return: オブジェクトに対応するバイト列
        """


# # ABCMetaとのメタクラスの衝突を避けるために、TLSObjectとは独立させる
# class TLSEnum[T: Enum](_TLSEnumBase, Enum, metaclass=ABCEnumMeta):
#     # @classmethod
#     # def byte_length(cls) -> int:
#     #     """Enumのバイトサイズ"""
#     #     raise NotImplementedError("定義されていません。")
#
#     @classmethod
#     def parse(cls, data: bytes) -> T:
#         raise NotImplementedError
#
#     @classmethod
#     def unparse(cls, obj: T) -> bytes:
#         raise NotImplementedError


class TLSIntEnum[T]:
    @classmethod
    def byte_length(cls) -> int:
        """Enumのバイトサイズ"""

    @classmethod
    def parse(cls, data: bytes) -> int:
        value = int.from_bytes(data, "big")
        for elem in cls:
            if value == elem:
                return elem
        raise ParseError("要素をパースできません")

    @classmethod
    def unparse(cls, obj: int):
        return obj.to_bytes(cls.byte_length(), "big")
