from reader import Block, Blocks, select, RestBlock
from pprint import pprint
from common import ExtensionType, HandshakeType
from extension.ec_point_formats import ECPointFormats
from extension.supported_versions import SupportedVersions
from record import TLSPlaintext, ContentType


if __name__ == '__main__':
    print(Blocks([
            Block(1, "byte", "int", after_parse=ContentType),
            Block(2, "byte", "int"),
            Block(2, "byte", "int"),
        ]).unparse(TLSPlaintext(ContentType.handshake, 0x0303, 257)))
