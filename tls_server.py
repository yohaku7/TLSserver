# -*- coding: UTF-8 -*-
import socket
import pprint

from alert import Alert
from extension.key_share import KeyShareClientHello, KeyShareServerHello, KeyShareEntry
from extension.psk_key_exchange_modes import PskKeyExchangeMode
from extension.extension_parser import ExtensionParser, extensions_rev
from handshake import Handshake, CipherSuite
from reader.bytes_reader import BytesBuilder
from record import ContentType, TLSPlaintext
from handshake import ClientHello, ServerHello
from common import HandshakeType, ExtensionType, NamedGroup
from reader import Blocks, Block, ListBlock, BytesReader, RestBlock

import secrets
from crypto import TLSKey


class TLSServer:
    def __init__(self, dst: str = "localhost", ip: int = 8080):
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__sock.bind((dst, ip))
        self.__conn = None
        self.__key = TLSKey()

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
        br = BytesReader(data)
        tls_plaintext: TLSPlaintext = br.read(TLSPlaintext.blocks)

        match tls_plaintext.type:
            case ContentType.handshake:
                handshake: Handshake = br.read(Handshake.blocks)
                match handshake.msg_type:
                    case HandshakeType.client_hello:
                        print(": ClientHello")
                        ch: ClientHello = br.read(ClientHello.blocks)
                        pprint.pprint(ch)
                        bb = BytesBuilder()
                        server_hello = self.make_server_hello(ch)
                        handshake = Handshake(HandshakeType.server_hello, len(server_hello.unparse()))
                        new_tls_plaintext = TLSPlaintext(ContentType.handshake, 0x0303, len(Handshake.blocks.unparse(handshake)) + len(server_hello.unparse()))
                        print(new_tls_plaintext)
                        print(handshake)
                        pprint.pprint(server_hello)
                        self.send(
                            TLSPlaintext.blocks.unparse(new_tls_plaintext) +
                            Handshake.blocks.unparse(handshake) +
                            server_hello.unparse()
                        )
            case ContentType.alert:
                print(": Alert")
                pprint.pprint(br.read(Alert.blocks))
                print("Exit.")
                exit(1)

    def make_server_hello(self, client_hello: ClientHello) -> ServerHello:
        legacy_version = 0x0303
        random = secrets.randbits(32 * 8)
        legacy_session_id_echo = client_hello.legacy_session_id
        # TLS_AES_128_GCM_SHA256を選択
        assert CipherSuite.TLS_AES_128_GCM_SHA256 in client_hello.cipher_suites
        cipher_suite = CipherSuite.TLS_AES_128_GCM_SHA256
        legacy_compression_method = 0
        # extensionsの作成
        extensions = []
        for client_extension in client_hello.extensions:
            if type(client_extension) in extensions_rev.keys():
                ext_type = extensions_rev[type(client_extension)]
                try:
                    reply = client_extension.reply()
                    print(reply.message)
                    if reply.obj is not None:
                        extensions.append(reply.obj)
                    else:
                        raise ValueError
                except:
                    match ext_type:
                        case ExtensionType.psk_key_exchange_modes:
                            if client_extension.ke_modes == PskKeyExchangeMode.psk_ke:
                                raise NotImplementedError("Can't process psk_ke.")
                            elif client_extension.ke_modes == PskKeyExchangeMode.psk_dhe_ke:
                                print("PskKeyExchangeMode: psk_dhe_ke")
                                for e in client_hello.extensions:
                                    if isinstance(e, KeyShareClientHello):
                                        self.__key.exchange_key_x25519(e.client_shares[0])
                                        # key_share_group = e.client_shares[0].group
                                        # assert key_share_group == NamedGroup.x25519
                                        # key_share_raw = e.client_shares[0].key_exchange
                                        # x25519_private_key = x25519.X25519PrivateKey.generate()
                                        # x25519_private_key.exchange(x25519.X25519PublicKey.from_public_bytes(key_share_raw))
                                        extensions.append(
                                            KeyShareServerHello(
                                                server_share=KeyShareEntry(
                                                    group=NamedGroup.x25519,
                                                    key_exchange=self.__key.server_x25519_public_key.public_bytes_raw()
                                                )
                                            )
                                        )
                        case ExtensionType.signature_algorithms:
                            pass
                        case _:
                            continue
            else:
                raise ValueError(f"Extensionを処理できません。 名前：{client_extension.__class__.__name__}")
            # match client_extension.type:
            #     case ExtensionType.ec_point_formats:
            #         assert 0 in client_extension.ec_point_formats
            #         print("ECPointFormat = 0 (uncompressed)")
            #     case ExtensionType.supported_versions:
            #         assert 0x0304 in client_extension.version
            #         print("Supported Versions: 0x0304 (TLS 1.3)")
            #         extensions.append(SupportedVersions([0x0304]))
            #     case ExtensionType.supported_groups:
            #         if NamedGroup.x25519 in client_extension.named_group_list:
            #             print("SupportedGroups: choose x25519")
            #         else: raise NotImplementedError("Can't choose x25519. Abort.")
            #     case ExtensionType.psk_key_exchange_modes:
            #         if client_extension.ke_modes == PskKeyExchangeMode.psk_ke:
            #             raise NotImplementedError("Can't process psk_ke.")
            #         elif client_extension.ke_modes == PskKeyExchangeMode.psk_dhe_ke:
            #             print("PskKeyExchangeMode: psk_dhe_ke")
            #             # assert KeyShareClientHello in client_hello.extensions
            #             for e in client_hello.extensions:
            #                 if e.type == ExtensionType.key_share:
            #                     key_share_group = e.client_shares[0].group
            #                     assert key_share_group == NamedGroup.x25519
            #                     key_share_raw = e.client_shares[0].key_exchange
            #             x25519_private_key = x25519.X25519PrivateKey.generate()
            #             x25519_private_key.exchange(x25519.X25519PublicKey.from_public_bytes(key_share_raw))
            #             extensions.append(
            #                 KeyShareServerHello(
            #                     server_share=KeyShareEntry(
            #                         group=NamedGroup.x25519,
            #                         key_exchange=x25519_private_key.private_bytes_raw()
            #                     )
            #                 )
            #             )
            #     case ExtensionType.signature_algorithms:
            #         pass
            #
            #     case _: continue

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
        print()
        print("------------------- Next --------------------")
        print()
        data = server.recv()


if __name__ == '__main__':
    main()
