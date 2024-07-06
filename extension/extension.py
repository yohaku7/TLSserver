# -*- coding: UTF-8 -*-
from dataclasses import dataclass

from .server_name import ServerName
from .supported_versions import SupportedVersions
from .extension_type import ExtensionType
from .ec_point_formats import ECPointFormats
from .supported_groups import SupportedGroups

from reader import BytesReader
from common import HandshakeType

__all__ = [
    "Extension"
]


@dataclass
class Extension:
    extension_type: ExtensionType
    extension_data: object

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType | None = None) -> list["Extension"]:
        extensions = []
        br = BytesReader(byte_seq)
        while br.rest_length != 0:
            print(byte_seq)
            extension_type = ExtensionType(br.read_byte(2, "int"))
            extension_data: bytes = br.read_variable_length(2, "raw")
            ext: object
            match extension_type:
                case ExtensionType.server_name:
                    ext = ServerName.parse(extension_data)
                case ExtensionType.supported_versions:
                    ext = SupportedVersions.parse(extension_data, handshake_type=handshake_type)
                case ExtensionType.ec_point_formats:
                    ext = ECPointFormats.parse(extension_data)
                case ExtensionType.supported_groups:
                    ext = SupportedGroups.parse(extension_data)
                case _:
                    raise ValueError(f"未対応のExtensionです。名前：{extension_type.name}")
            print(ext)
            extensions.append(Extension(extension_type, ext))
        return extensions

    @staticmethod
    def unparse(byte_seq: bytes):
        pass
