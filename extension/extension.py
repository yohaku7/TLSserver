# -*- coding: UTF-8 -*-
from dataclasses import dataclass

from .server_name import ServerName
from .supported_versions import SupportedVersions
from .extension_type import ExtensionType
from .ec_point_formats import ECPointFormats
from .supported_groups import SupportedGroups
from .renegotiation_info import RenegotiationInfo
from .session_ticket import SessionTicket
from .key_share import KeyShareServerHello, KeyShareClientHello, KeyShareHelloRetryRequest
from .signature_algorithms import SignatureAlgorithms, SignatureAlgorithmsCert

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
                case ExtensionType.session_ticket:
                    ext = SessionTicket.parse(extension_data)
                case ExtensionType.renegotiation_info:
                    ext = RenegotiationInfo.parse(extension_data)
                case ExtensionType.key_share:
                    match handshake_type:
                        case HandshakeType.client_hello:
                            ext = KeyShareClientHello.parse(extension_data)
                        case HandshakeType.server_hello:
                            ext = KeyShareServerHello.parse(extension_data)
                        case _:
                            raise ValueError("HelloRetryRequestですか？key_shareはパースできません")
                case ExtensionType.signature_algorithms:
                    ext = SignatureAlgorithms.parse(extension_data)
                case ExtensionType.signature_algorithms_cert:
                    ext = SignatureAlgorithmsCert.parse(extension_data)
                case _:
                    raise ValueError(f"未対応のExtensionです。名前：{extension_type.name}")
            print(ext)
            extensions.append(Extension(extension_type, ext))
        return extensions

    @staticmethod
    def unparse(byte_seq: bytes):
        pass
