# -*- coding: UTF-8 -*-
from enum import IntEnum
from dataclasses import dataclass
from abc import ABCMeta, abstractmethod

from reader import BytesReader
from .server_name import ServerName
from .supported_versions import SupportedVersions

__all__ = [
    "ExtensionType",
    "Extension"
]

from ..handshake import HandshakeType


class ExtensionType(IntEnum):
    server_name = 0
    max_fragment_length = 1
    status_request = 5
    supported_groups = 10
    signature_algorithms = 13
    use_srtp = 14
    heartbeat = 15
    application_layer_protocol_negotiation = 16
    signed_certificate_timestamp = 18
    client_certificate_type = 19
    server_certificate_type = 20
    padding = 21
    pre_shared_key = 41
    early_data = 42
    supported_versions = 43
    cookie = 44
    psk_key_exchange_modes = 45
    certificate_authorities = 47
    oid_filters = 48
    post_handshake_auth = 49
    signature_algorithms_cert = 50
    key_share = 51
    # 65535


@dataclass
class Extension(metaclass=ABCMeta):
    extension_type: ExtensionType
    extension_data: object

    @staticmethod
    @abstractmethod
    def parse(byte_seq: bytes) -> list["Extension"]:
        extensions = []
        br = BytesReader(byte_seq)
        while br.rest_length != 0:
            print(byte_seq)
            extension_type = ExtensionType(br.read_byte(2, "int"))
            extension_data: bytes = br.read_variable_length(2, "raw")
            match extension_type:
                case ExtensionType.server_name:
                    sn = ServerName.parse(extension_data)
                    extensions.append(Extension(extension_type, sn))
                case ExtensionType.supported_versions:
                    sv = SupportedVersions.parse(extension_data, handshake_type=HandshakeType.server_hello)
                case _:
                    raise ValueError("未対応のExtensionです。")
        return extensions

    @staticmethod
    @abstractmethod
    def unparse(byte_seq: bytes):
        pass
