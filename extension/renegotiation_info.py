from dataclasses import dataclass
from reader import Block, Blocks
from .extension_data import ExtensionData


@dataclass(frozen=True)
class RenegotiationInfo(ExtensionData):
    renegotiated_connection: bytes
    blocks = Blocks([
        Block(1, "byte", "raw", variable=True)
    ])


RenegotiationInfo.blocks.after_parse_factory = RenegotiationInfo
