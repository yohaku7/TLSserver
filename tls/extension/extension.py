# -*- coding: UTF-8 -*-
from enum import IntEnum
from dataclasses import dataclass
from abc import ABCMeta, abstractmethod

from reader.bytes_reader import BytesReader


__all__ = [
    "ExtensionType",
    "Extension"
]


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
    extension_data: str

    @staticmethod
    def parse(byte_seq: bytes) -> ("Extension", bytes):
        br = BytesReader(byte_seq)
        extension_type = br.read_byte(2, "int")
        extension_type = ExtensionType(extension_type)
        extension_data = br.read_variable_length(2, "raw")
        extension_data = Extension._data_parse(extension_data)  # extension_dataのパース
        return Extension(extension_type, extension_data)
