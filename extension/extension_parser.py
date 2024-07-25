# -*- coding: UTF-8 -*-
from .server_name import ServerName
from .supported_versions import SupportedVersions
from .ec_point_formats import ECPointFormats
from .supported_groups import SupportedGroups
from .renegotiation_info import RenegotiationInfo
from .session_ticket import SessionTicket
from .key_share import KeyShare, KeyShareServerHello, KeyShareClientHello
from .encrypt_then_mac import EncryptThenMAC
from .extended_master_secret import ExtendedMasterSecret
from .psk_key_exchange_modes import PskKeyExchangeModes
from .signature_algorithms import SignatureAlgorithms, SignatureAlgorithmsCert
from .record_size_limit import RecordSizeLimit

from .extension_data import ExtensionData

from reader import BytesReader, Block, Blocks
from common import HandshakeType, ExtensionType

__all__ = [
    "ExtensionParser",
    "extensions_rev"
]

extensions: dict[ExtensionType, type[ExtensionData]] = {
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
    ExtensionType.psk_key_exchange_modes: PskKeyExchangeModes,
    ExtensionType.record_size_limit: RecordSizeLimit,
}
extensions_rev: dict[type[ExtensionData], ExtensionType] = {v: k for k, v in extensions.items()}
extensions_rev[KeyShareServerHello] = ExtensionType.key_share
extensions_rev[KeyShareClientHello] = ExtensionType.key_share

_blocks = Blocks([
    Block(2, "byte", "int", after_parse=ExtensionType),
    Block(2, "byte", "raw", variable=True)
])


class ExtensionParser:
    @staticmethod
    def parse(byte_seq: bytes, handshake_type: HandshakeType) -> list[ExtensionData]:
        result = []
        br = BytesReader(byte_seq)
        while br.rest_length != 0:
            extension_type, extension_data = _blocks.parse(br)
            if extension_type in extensions.keys():
                try:
                    ext = extensions[extension_type].parse(extension_data, handshake_type)
                except NotImplementedError:
                    ext = extensions[extension_type].blocks.from_bytes(extension_data)
            else:
                raise ValueError(f"未対応のExtensionです。名前：{extension_type.name}")
            result.append(ext)
        return result

    @staticmethod
    def unparse(extension_data: list[ExtensionData], handshake_type: HandshakeType):
        result = b""
        for ext in extension_data:
            if type(ext) in extensions_rev.keys():
                try:
                    result += _blocks.unparse(extensions_rev[type(ext)].value,
                                              ext.unparse(handshake_type))
                except NotImplementedError:
                    result += _blocks.unparse(extensions_rev[type(ext)].value,
                                              type(ext).blocks.unparse(ext))
            else:
                raise ValueError("Couldn't unparse.")
        return result
