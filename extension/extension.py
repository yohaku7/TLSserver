# -*- coding: UTF-8 -*-
from dataclasses import dataclass

from .server_name import ServerName
from .supported_versions import SupportedVersions
from .ec_point_formats import ECPointFormats
from .supported_groups import SupportedGroups
from .renegotiation_info import RenegotiationInfo
from .session_ticket import SessionTicket
from .key_share import KeyShare
from .encrypt_then_mac import EncryptThenMAC
from .extended_master_secret import ExtendedMasterSecret
from .signature_algorithms import SignatureAlgorithms, SignatureAlgorithmsCert

from reader import BytesReader
from common import HandshakeType, ExtensionType

__all__ = [
    "Extension"
]

extensions = {
    ExtensionType.server_name: ServerName,
    ExtensionType.supported_versions: SupportedVersions,
    ExtensionType.ec_point_formats: ECPointFormats,
    ExtensionType.supported_groups: SupportedGroups,
    ExtensionType.session_ticket: SessionTicket,
    ExtensionType.renegotiation_info: RenegotiationInfo,
    ExtensionType.key_share: KeyShare,
    ExtensionType.signature_algorithms: SignatureAlgorithms,
    ExtensionType.signature_algorithms_cert: SignatureAlgorithmsCert,
    ExtensionType.encrypt_then_mac: EncryptThenMAC,
    ExtensionType.extended_master_secret: ExtendedMasterSecret,
}


@dataclass
class Extension:
    extension_type: ExtensionType
    extension_data: object

    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType | None = None) -> list["Extension"]:
        result = []
        br = BytesReader(byte_seq)

        while br.rest_length != 0:
            extension_type = ExtensionType(br.read_byte(2, "int"))
            extension_data: bytes = br.read_variable_length(2, "raw")
            ext: object
            if extension_type in extensions.keys():
                ext = extensions[extension_type].parse(extension_data, handshake_type)
            else:
                raise ValueError(f"未対応のExtensionです。名前：{extension_type.name}")
            print(ext)
            result.append(Extension(extension_type, ext))
        return result

    def unparse(self, handshake_type: HandshakeType):
        res = b""
        res += self.extension_type.value.to_bytes(length=2)
        res += self.extension_data.unparse(handshake_type)
        return res
