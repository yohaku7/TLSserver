# -*- coding: UTF-8 -*-
from dataclasses import dataclass

from common import ExtensionType
from reader import new

from .ec_point_formats import ECPointFormats
from .encrypt_then_mac import EncryptThenMAC
from .extended_master_secret import ExtendedMasterSecret
from .key_share import KeyShare
from .pre_shared_key import PreSharedKey
from .psk_key_exchange_modes import PskKeyExchangeModes
from .record_size_limit import RecordSizeLimit
from .renegotiation_info import RenegotiationInfo
from .server_name import ServerName
from .session_ticket import SessionTicket
from .signature_algorithms import SignatureAlgorithms, SignatureAlgorithmsCert
from .supported_groups import SupportedGroups
from .supported_versions import SupportedVersions

__all__ = [
    "extensions"
]

extensions: dict[ExtensionType, type[new.TLSObject]] = {
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
    ExtensionType.pre_shared_key: PreSharedKey,
}


@dataclass(frozen=True)
class ExtensionHeader(new.TLSObject):
    type: ExtensionType
    content: bytes

    @classmethod
    def _get_lengths(cls) -> list[int | tuple | None]:
        return [
            2,
            (2, True),
        ]
