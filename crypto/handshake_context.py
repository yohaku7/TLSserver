from dataclasses import dataclass
from reader import new
from .tls_key import TLSKey


@dataclass
class HandshakeContext:
    __handshakes: list[new.TLSObject]

    def append(self, handshake: new.TLSObject):
        self.__handshakes.append(handshake)

    @property
    def handshakes(self):
        return self.__handshakes

    @property
    def transcript_hash(self):
        return TLSKey.Transcript_Hash(*self.__handshakes)
