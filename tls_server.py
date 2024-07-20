# -*- coding: UTF-8 -*-
import socket
import pprint

from extension import SupportedVersions
from extension.key_share import KeyShareClientHello, KeyShareServerHello, KeyShareEntry
from extension.psk_key_exchange_modes import PskKeyExchangeMode
from handshake import Handshake
from record import ContentType, TLSPlaintext
from handshake import ClientHello, ServerHello
from common import HandshakeType, ExtensionType, NamedGroup

import secrets

from cryptography.hazmat.primitives.asymmetric import x25519


class TLSServer:
    def __init__(self, dst: str = "localhost", ip: int = 8080):
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__sock.bind((dst, ip))
        self.__conn = None

    def __del__(self):
        self.close()

    def close(self):
        self.__sock.close()

    def accept_and_recv(self):
        self.__sock.listen(1)
        conn, addr = self.__sock.accept()
        self.__conn = conn
        print(f"接続：{addr}")
        data = self.__conn.recv(65565)
        return data

    def send(self, data: bytes):
        self.__conn.send(data)

    def recv(self):
        data = self.__conn.recv(65565)
        return data

    def parse(self, data: bytes) -> None:
        parsed = TLSPlaintext.parse(data)
        match parsed.type:
            case ContentType.handshake:
                match parsed.fragment.msg_type:
                    case HandshakeType.client_hello:
                        print(": ClientHello")
                        pprint.pprint(parsed.fragment.message)
                        server_hello = self.make_server_hello(parsed.fragment.message)
                        handshake = Handshake(
                            msg_type=HandshakeType.server_hello, length=len(server_hello.unparse()),
                            message=server_hello
                        )
                        self.send(
                            TLSPlaintext(ContentType.handshake, 0x0303,
                                         len(handshake.unparse()), handshake).unparse())
            case ContentType.alert:
                print(": Alert")
                pprint.pprint(parsed.fragment)
                print("Exit.")
                exit(1)

    def make_server_hello(self, client_hello: ClientHello) -> ServerHello:
        legacy_version = 0x0303
        random = secrets.randbits(32 * 8)
        legacy_session_id_echo = client_hello.legacy_session_id
        # 最初のCipherSuiteを選択する
        cipher_suite = client_hello.cipher_suites[0]
        legacy_compression_method = 0
        # extensionsの作成
        extensions = []
        for client_extension in client_hello.extensions:
            match client_extension.type:
                case ExtensionType.ec_point_formats:
                    assert 0 in client_extension.ec_point_formats
                    print("ECPointFormat = 0 (uncompressed)")
                case ExtensionType.supported_versions:
                    assert 0x0304 in client_extension.version
                    print("Supported Versions: 0x0304 (TLS 1.3)")
                    extensions.append(SupportedVersions([0x0304]))
                case ExtensionType.supported_groups:
                    if NamedGroup.x25519 in client_extension.named_group_list:
                        print("SupportedGroups: choose x25519")
                    else: raise NotImplementedError("Can't choose x25519. Abort.")
                case ExtensionType.psk_key_exchange_modes:
                    if client_extension.ke_modes == PskKeyExchangeMode.psk_ke:
                        raise NotImplementedError("Can't process psk_ke.")
                    elif client_extension.ke_modes == PskKeyExchangeMode.psk_dhe_ke:
                        print("PskKeyExchangeMode: psk_dhe_ke")
                        # assert KeyShareClientHello in client_hello.extensions
                        for e in client_hello.extensions:
                            if e.type == ExtensionType.key_share:
                                key_share_group = e.client_shares[0].group
                                assert key_share_group == NamedGroup.x25519
                                key_share_raw = e.client_shares[0].key_exchange
                        x25519_private_key = x25519.X25519PrivateKey.generate()
                        x25519_private_key.exchange(x25519.X25519PublicKey.from_public_bytes(key_share_raw))
                        extensions.append(
                            KeyShareServerHello(
                                server_share=KeyShareEntry(
                                    group=NamedGroup.x25519,
                                    key_exchange=x25519_private_key.private_bytes_raw()
                                )
                            )
                        )
                case ExtensionType.signature_algorithms:
                    pass

                case _: continue

        return ServerHello(
            legacy_version, random,
            legacy_session_id_echo, cipher_suite,
            legacy_compression_method, extensions
        )


def main():
    server = TLSServer()
    data = server.accept_and_recv()
    # data = bytes.fromhex("16030100c4010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001")
    while True:
        server.parse(data)
        # tp = TLSPlaintext.parse(data)
        # print("----- TLSPlaintext -----")
        # pprint.pprint(tp)
        # match tp.type:
        #     case ContentType.handshake:
        #         match tp.fragment.msg_type:
        #             case HandshakeType.client_hello:
        #                 server_hello = ServerHello.make(tp.fragment.message)
        #                 handshake = Handshake(HandshakeType.server_hello, len(server_hello.unparse()), server_hello)
        #                 record = TLSPlaintext(ContentType.handshake, 0x0303, len(handshake.unparse()), handshake)
        #                 pprint.pprint(record)
        #                 print(record.unparse().hex())
        #                 server.send(record.unparse())
        #     case ContentType.alert:
        #         print("----- Alert -----")
        #         pprint.pprint(tp.fragment)
        #         break
        print()
        print("------------------- Next --------------------")
        print()
        data = server.recv()


if __name__ == '__main__':
    main()
