from dataclasses import dataclass


from common import NamedGroup
from reader import BytesReader


@dataclass
class KeyShareEntry:
    group: NamedGroup
    key_exchange: bytes


@dataclass
class KeyShareClientHello:
    client_shares: list[KeyShareEntry]

    @staticmethod
    def parse(byte_seq: bytes):
        br = BytesReader(byte_seq)
        client_shares_raw = br.read_variable_length(2, "raw")
        br = BytesReader(client_shares_raw)
        res = []
        while br.rest_length != 0:
            group = br.read_byte(2, "int")
            key_exchange = br.read_variable_length(2, "raw")
            res.append(KeyShareEntry(NamedGroup(group), key_exchange))
        return KeyShareClientHello(res)


@dataclass
class KeyShareHelloRetryRequest:
    selected_group: NamedGroup

    @staticmethod
    def parse(byte_seq: bytes):
        br = BytesReader(byte_seq)
        return KeyShareHelloRetryRequest(NamedGroup(br.read_byte(2, "int")))


@dataclass
class KeyShareServerHello:
    server_share: KeyShareEntry

    @staticmethod
    def parse(byte_seq: bytes):
        br = BytesReader(byte_seq)
        group = NamedGroup(br.read_byte(2, "int"))
        key_exchange = br.read_variable_length(2, "raw")
        return KeyShareServerHello(KeyShareEntry(group, key_exchange))
