# -*- coding: UTF-8 -*-
import socket
import pprint

from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256

from alert import Alert
from extension import ServerName
from extension.key_share import KeyShareClientHello, KeyShareServerHello, KeyShareEntry
from extension.psk_key_exchange_modes import PskKeyExchangeMode
from extension.extension_parser import extensions_rev
from handshake import Handshake, CipherSuite, EncryptedExtensions
from handshake.certificate import Certificate
from handshake.certificate_verify import CertificateVerify
from handshake.finished import Finished
from reader import BytesReader, Blocks, Block, EnumBlock
from record import TLSPlaintext, TLSCiphertext
from handshake import ClientHello, ServerHello
from common import ContentType, HandshakeType, ExtensionType, NamedGroup, SignatureScheme

import secrets
from crypto import TLSKey
from record.tls_inner_plaintext import TLSInnerPlaintext


class TLSServer:
    def __init__(self, dst: str = "localhost", ip: int = 8080):
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 接続の高速化
        self.__sock.bind((dst, ip))
        self.__conn = None
        self.__key = TLSKey()
        self.__handshake_ctx = []
        self.handshake_finished = False

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

    def parse(self, data: bytes):
        br = BytesReader(data)
        content_type, lrv, length = Blocks([
            Block(1, "int", after_parse=ContentType),
            Block(2, "int"),
            Block(2, "int"),
        ]).parse(br)
        read_data = br.read_byte(length, "raw")
        print(f"DATA: {read_data}")

        match content_type:
            case ContentType.handshake:
                handshake: Handshake = Handshake.blocks.from_bytes(read_data)
                match handshake.msg_type:
                    case HandshakeType.client_hello:
                        print(": ClientHello")
                        ch: ClientHello = ClientHello.blocks.from_bytes(handshake.msg)
                        self.__handshake_ctx.append(ch)
                        pprint.pprint(ch)
                        server_hello = self.make_server_hello(ch)
                        self.__handshake_ctx.append(server_hello)
                        handshake = Handshake.make(server_hello)
                        new_tls_plaintext = TLSPlaintext.make(handshake)
                        pprint.pprint(server_hello)
                        self.send(TLSPlaintext.blocks.unparse(new_tls_plaintext))
                        # make encrypted_extensions
                        self.__key.derive_secrets(None, ch, server_hello)
                        ee = self.make_encrypted_extensions()
                        self.__handshake_ctx.append(ee)
                        new_handshake = Handshake.make(ee)
                        tls_inner_plaintext = TLSInnerPlaintext(
                            Handshake.blocks.unparse(new_handshake), ContentType.handshake, b""
                        )
                        # Refer: RFC8446 §5.2 "length: The length ..."
                        # Refer: https://tex2e.github.io/rfc-translater/html/rfc5116.html#2-1--Authenticated-Encryption
                        tls_ciphertext_len = len(tls_inner_plaintext.unparse()) + 16
                        encrypted_tls_inner_plaintext, tag = self.__key.encrypt_handshake(tls_inner_plaintext.unparse(),
                                                                                          ContentType.application_data,
                                                                                          0x0303,
                                                                                          tls_ciphertext_len)
                        encrypted_tls_inner_plaintext += tag
                        print(tls_ciphertext_len, encrypted_tls_inner_plaintext, len(encrypted_tls_inner_plaintext))
                        tls_ciphertext = TLSCiphertext(
                            ContentType.application_data, 0x0303, len(encrypted_tls_inner_plaintext),
                            encrypted_tls_inner_plaintext
                        )
                        self.send(TLSCiphertext.blocks.unparse(tls_ciphertext))

                        # make certificate
                        certificate, real_cert = self.make_certificate()
                        self.__handshake_ctx.append(real_cert)
                        self.send(TLSCiphertext.blocks.unparse(certificate))

                        # make certificate_verify
                        cv, real_cv = self.make_certificate_verify(ch, server_hello, ee, real_cert)
                        self.__handshake_ctx.append(real_cv)
                        self.send(TLSCiphertext.blocks.unparse(cv))

                        # make finished
                        finished, real_finished = self.make_finished(*self.__handshake_ctx)
                        self.__handshake_ctx.append(real_finished)
                        self.send(TLSCiphertext.blocks.unparse(finished))
            case ContentType.alert:
                print(": Alert")
                pprint.pprint(Alert.blocks.from_bytes(read_data))
                print("Exit.")
                exit(1)
            case ContentType.change_cipher_spec:
                print("ChangeCipherSpec, ignore.")
            case ContentType.application_data:
                print("Application Data.")
                assert length == len(read_data)
                decrypted = self.__key.decrypt_handshake(read_data, ContentType.application_data, 0x0303, length)
                print(f"decrypted: {decrypted}")
                tls_inner_plaintext = TLSInnerPlaintext.from_bytes(decrypted)
                print(tls_inner_plaintext)
                handshake = Handshake.blocks.from_bytes(tls_inner_plaintext.content)
                print(handshake)
                self.check_client_finished(handshake.msg, *self.__handshake_ctx)
                self.handshake_finished = True
                self.__key.make_application_key(self.__handshake_ctx, Finished(handshake.msg))
            case _:
                raise ValueError

        if br.rest_length != 0:
            self.parse(br.rest_bytes())

    def parse_application_data(self, data: bytes):
        decrypted = self.__key.decrypt_application_data(data, ContentType.application_data,
                                                        0x0303, len(data))
        tls_inner_plaintext = TLSInnerPlaintext.from_bytes(decrypted)
        self.__key.seq_upd_client()
        print(f"受信: {tls_inner_plaintext.content}")

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
                        case ExtensionType.signature_algorithms:
                            for e in client_hello.extensions:
                                if isinstance(e, KeyShareClientHello):
                                    self.__key.exchange_key_x25519(e.client_shares[0])
                                    extensions.append(
                                        KeyShareServerHello(
                                            server_share=KeyShareEntry(
                                                group=NamedGroup.x25519,
                                                key_exchange=self.__key.server_x25519_public_key.public_bytes_raw()
                                            )
                                        )
                                    )
                        case _:
                            continue
            else:
                raise ValueError(f"Extensionを処理できません。 名前：{client_extension.__class__.__name__}")
        return ServerHello(
            legacy_version, random,
            legacy_session_id_echo, cipher_suite,
            legacy_compression_method, extensions
        )

    def make_encrypted_extensions(self):
        sn = ServerName(name="www.yohaku7.jp")
        return EncryptedExtensions([])

    def check_client_finished(self, verify_data: bytes, ch, sh, ee, cert, cv, s_finished):
        assert len(verify_data) == 32
        finished_key = TLSKey.HKDF_Expand_Label(self.__key.client_handshake_traffic_secret,
                                                b"finished", b"", 32)
        actual_verify_data = TLSKey.HMAC(finished_key,
                                         TLSKey.Transcript_Hash(ch, sh, ee, cert, cv, s_finished))
        assert actual_verify_data == verify_data

    def make_finished(self, ch, sh, ee, cert, cv):
        self.__key.seq_upd_server()
        finished_key = TLSKey.HKDF_Expand_Label(self.__key.server_handshake_traffic_secret,
                                                b"finished", b"", 32)
        verify_data = TLSKey.HMAC(finished_key, TLSKey.Transcript_Hash(ch, sh, ee, cert, cv))
        finished = Finished(verify_data)
        handshake = Handshake.make(finished)
        tls_inner_plaintext = TLSInnerPlaintext(handshake.blocks.unparse(handshake), ContentType.handshake, b"")
        tls_ciphertext_len = len(tls_inner_plaintext.unparse()) + 16
        encrypted_tls_inner_plaintext, tag = self.__key.encrypt_handshake(tls_inner_plaintext.unparse(),
                                                                          ContentType.application_data,
                                                                          0x0303,
                                                                          tls_ciphertext_len)
        encrypted_tls_inner_plaintext += tag
        tls_ciphertext = TLSCiphertext(
            ContentType.application_data, 0x0303, len(encrypted_tls_inner_plaintext),
            encrypted_tls_inner_plaintext
        )
        return tls_ciphertext, finished

    def make_certificate(self) -> (TLSCiphertext, Certificate):
        cert = TLSKey.load_x509_cert("temp/cert.pem")
        cert = cert.public_bytes(Encoding.DER)
        certificate = Certificate.make(cert, [])
        self.__key.seq_upd_server()
        handshake = Handshake.make(certificate)
        tls_inner_plaintext = TLSInnerPlaintext(handshake.blocks.unparse(handshake), ContentType.handshake, b"")
        tls_ciphertext_len = len(tls_inner_plaintext.unparse()) + 16
        encrypted_tls_inner_plaintext, tag = self.__key.encrypt_handshake(tls_inner_plaintext.unparse(),
                                                                          ContentType.application_data,
                                                                          0x0303,
                                                                          tls_ciphertext_len)
        encrypted_tls_inner_plaintext += tag
        tls_ciphertext = TLSCiphertext(
            ContentType.application_data, 0x0303, len(encrypted_tls_inner_plaintext),
            encrypted_tls_inner_plaintext
        )
        return tls_ciphertext, certificate

    def make_certificate_verify(self, ch, sh, ee, cert) -> (TLSCiphertext, CertificateVerify):
        self.__key.seq_upd_server()
        algorithm = SignatureScheme.ecdsa_secp256r1_sha256
        signature_content = TLSKey.Transcript_Hash(ch, sh, ee, cert)
        signature_content = (  # refer: TLS8446 §4.4.3
            b"\x20" * 64 +
            b"TLS 1.3, server CertificateVerify" +
            b"\x00" +
            signature_content
        )
        private_key = TLSKey.load_x509_key("temp/key.pem")
        signature = private_key.sign(signature_content, ECDSA(SHA256()))
        cv = CertificateVerify(algorithm, signature)
        handshake = Handshake.make(cv)
        tls_inner_plaintext = TLSInnerPlaintext(handshake.blocks.unparse(handshake), ContentType.handshake, b"")
        tls_ciphertext_len = len(tls_inner_plaintext.unparse()) + 16
        encrypted_tls_inner_plaintext, tag = self.__key.encrypt_handshake(tls_inner_plaintext.unparse(),
                                                                          ContentType.application_data,
                                                                          0x0303,
                                                                          tls_ciphertext_len)
        encrypted_tls_inner_plaintext += tag
        tls_ciphertext = TLSCiphertext(
            ContentType.application_data, 0x0303, len(encrypted_tls_inner_plaintext),
            encrypted_tls_inner_plaintext
        )
        return tls_ciphertext, cv


def main():
    server = TLSServer()
    data = server.accept_and_recv()
    while True:
        server.parse(data)
        if server.handshake_finished:
            print("HANDSHAKE FINISHED!")
            break
        else:
            print()
            print("------------------- Next --------------------")
            print()
            data = server.recv()
    while True:
        data = server.recv()
        tls_ciphertext = TLSCiphertext.blocks.from_bytes(data)
        print(tls_ciphertext)
        server.parse_application_data(tls_ciphertext.encrypted_record)
        print()
        print("------------------- Next --------------------")
        print()


if __name__ == '__main__':
    main()
