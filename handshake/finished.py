from typing import ClassVar
from dataclasses import dataclass

from reader import Blocks, Block
from .tls_handshake import TLSHandshake


"""
   +-----------+-------------------------+-----------------------------+
   | Mode      | Handshake Context       | Base Key                    |
   +-----------+-------------------------+-----------------------------+
   | Server    | ClientHello ... later   | server_handshake_traffic_   |
   |           | of EncryptedExtensions/ | secret                      |
   |           | CertificateRequest      |                             |
   |           |                         |                             |
   | Client    | ClientHello ... later   | client_handshake_traffic_   |
   |           | of server               | secret                      |
   |           | Finished/EndOfEarlyData |                             |
   |           |                         |                             |
   | Post-     | ClientHello ... client  | client_application_traffic_ |
   | Handshake | Finished +              | secret_N                    |
   |           | CertificateRequest      |                             |
   +-----------+-------------------------+-----------------------------+
"""


@dataclass(frozen=True)
class Finished(TLSHandshake):
    verify_data: bytes

    blocks: ClassVar[Blocks] = Blocks([
        Block(32, "raw")
    ])

    def unparse(self):
        return Finished.blocks.unparse(self)
