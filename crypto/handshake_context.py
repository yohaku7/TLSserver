from dataclasses import dataclass
from handshake.tls_handshake import TLSHandshake
from .tls_key import TLSKey


@dataclass
class HandshakeContext:
    __handshakes: list[TLSHandshake]

    def append(self, handshake: TLSHandshake):
        self.__handshakes.append(handshake)

    @property
    def handshakes(self):
        return self.__handshakes

    @property
    def transcript_hash(self):
        return TLSKey.Transcript_Hash(*self.__handshakes)
