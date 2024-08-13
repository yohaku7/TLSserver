from common import ContentType
from dataclasses import dataclass
from reader import new

__all__ = ["TLSPlaintext"]

from .tls_record_obj import TLSRecordObj
from handshake import Handshake
from alert import Alert


content_types: dict[type[TLSRecordObj], ContentType] = {
    Handshake: ContentType.handshake,
    Alert: ContentType.alert,
}


@dataclass(frozen=True)
class TLSPlaintext(new.TLSObject):
    type: ContentType
    legacy_record_version: int
    length: int
    fragment: bytes

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            1,
            2,
            2,
            -1
        ]

    @staticmethod
    def make(obj: TLSRecordObj):
        if not type(obj) in content_types:
            raise ValueError("TLSRecordObjをパースできません")
        c_type = content_types[type(obj)]
        lr_version = 0x0303
        fragment = obj.unparse()
        length = len(fragment)
        return TLSPlaintext(c_type, lr_version, length, fragment)
