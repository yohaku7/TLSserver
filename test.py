from reader import Block
from common import ExtensionType, HandshakeType
from extension.ec_point_formats import ECPointFormats
from extension.supported_versions import SupportedVersions

if __name__ == '__main__':
    e = ECPointFormats.parse(b"\x00", HandshakeType.client_hello)
    print(e)
    s = SupportedVersions([0x0304]).unparse(HandshakeType.server_hello)
    print(s)
