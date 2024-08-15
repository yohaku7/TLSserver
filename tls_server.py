# -*- coding: UTF-8 -*-
import socket
import pprint

from cryptography.hazmat.primitives._serialization import Encoding

from alert import Alert
from alert.alert import AlertDescription
from crypto.elliptic import ECPrivateKey, ECDSA
from extension.key_share import KeyShareClientHello, KeyShareServerHello, KeyShareEntry
from extension.psk_key_exchange_modes import PskKeyExchangeMode
from extension.extension_parser import ExtensionHeader, extensions
from extension.supported_versions import SupportedVersionsServerHello
from handshake import Handshake, CipherSuite, EncryptedExtensions
from handshake.certificate import Certificate
from handshake.certificate_verify import CertificateVerify
from handshake.finished import Finished
from reader import BytesReader, Blocks, Block
from record import TLSPlaintext, TLSCiphertext
from handshake import ClientHello, ServerHello
from common import ContentType, HandshakeType, ExtensionType, NamedGroup, SignatureScheme

import secrets
import hashlib
from crypto import TLSKey, HandshakeContext, elliptic
from record.tls_inner_plaintext import TLSInnerPlaintext


class TLSServer:
    def __init__(self, dst: str = "localhost", ip: int = 8080):
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 接続の高速化
        self.__sock.bind((dst, ip))
        self.__conn = None
        self.__key = TLSKey()
        self.__handshake_ctx = HandshakeContext([])
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
                handshake: Handshake = Handshake.from_bytes(read_data)
                match handshake.msg_type:
                    case HandshakeType.client_hello:
                        print(": ClientHello")
                        ch: ClientHello = ClientHello.from_bytes(handshake.msg)
                        pprint.pprint(ch)
                        print(ch.unparse().hex())
                        self.__handshake_ctx.append(ch)

                        sh = self.make_server_hello(ch)
                        self.__handshake_ctx.append(sh)
                        handshake = Handshake.make(sh)
                        new_tls_plaintext = TLSPlaintext.make(handshake)
                        self.send(TLSPlaintext.unparse(new_tls_plaintext))

                        # make encrypted_extensions
                        self.__key.derive_secrets(None, ch, sh)
                        ee = self.make_encrypted_extensions()
                        self.send(TLSCiphertext.unparse(ee))

                        # make certificate
                        certificate = self.make_certificate()
                        self.send(TLSCiphertext.unparse(certificate))

                        # make certificate_verify
                        cv = self.make_certificate_verify()
                        self.send(TLSCiphertext.unparse(cv))

                        # make finished
                        finished = self.make_finished()
                        self.send(TLSCiphertext.unparse(finished))
            case ContentType.alert:
                print(": Alert")
                alert = Alert.from_bytes(read_data)
                print(alert)
                if alert.description == AlertDescription.close_notify:
                    print(": Close Notify")
                    # TODO: send close notify
                    exit(0)
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
                handshake = Handshake.from_bytes(tls_inner_plaintext.content)
                print(handshake)
                self.check_client_finished(handshake.msg)
                self.handshake_finished = True
                self.__key.make_application_key(self.__handshake_ctx.handshakes, Finished(handshake.msg))
            case _:
                raise ValueError

        if br.rest_length != 0:
            self.parse(br.rest_bytes())

    def parse_application_data(self, data: bytes):
        decrypted = self.__key.decrypt_application_data(data, ContentType.application_data,
                                                        0x0303, len(data))
        tls_inner_plaintext = TLSInnerPlaintext.from_bytes(decrypted)
        match tls_inner_plaintext.type:
            case ContentType.application_data:
                print(f"受信: {tls_inner_plaintext.content}")
            case ContentType.alert:
                print(Alert.from_bytes(tls_inner_plaintext.content))
                exit(0)
        self.__key.seq_upd_client()

    def make_server_hello(self, client_hello: ClientHello) -> ServerHello:
        legacy_version = 0x0303
        random = secrets.randbits(32 * 8)
        legacy_session_id_echo = client_hello.legacy_session_id
        # TLS_AES_128_GCM_SHA256を選択
        assert CipherSuite.TLS_AES_128_GCM_SHA256 in client_hello.cipher_suites
        cipher_suite = CipherSuite.TLS_AES_128_GCM_SHA256
        legacy_compression_method = 0
        # extensionsの作成
        server_extensions = []
        for ext in client_hello.extensions:
            if ext.type in extensions.keys():
                content = extensions[ext.type].from_bytes(ext.content, **{"handshake_type": HandshakeType.client_hello})
                try:
                    reply = content.reply()
                    print(reply.message)
                    if reply.obj is not None:
                        server_extensions.append(reply.obj)
                    else:
                        raise ValueError
                except:
                    match ext.type:
                        case ExtensionType.supported_versions:
                            assert 0x0304 in content.version
                            server_extensions.append(
                                ExtensionHeader(
                                    ExtensionType.supported_versions,
                                    SupportedVersionsServerHello(0x0304).unparse()
                                )
                            )
                        case ExtensionType.psk_key_exchange_modes:
                            if content.ke_modes == PskKeyExchangeMode.psk_ke:
                                raise NotImplementedError("Can't process psk_ke.")
                            elif content.ke_modes == PskKeyExchangeMode.psk_dhe_ke:
                                pass
                        case ExtensionType.signature_algorithms:
                            for e in client_hello.extensions:
                                if e.type == ExtensionType.key_share:
                                    con = KeyShareClientHello.from_bytes(e.content)
                                    self.__key.exchange_key_x25519(con.client_shares[0])
                                    server_extensions.append(
                                        ExtensionHeader(
                                            ExtensionType.key_share,
                                            KeyShareServerHello(
                                                server_share=KeyShareEntry(
                                                    group=NamedGroup.x25519,
                                                    key_exchange=self.__key.server_x25519_public_key.public_bytes_raw()
                                                )
                                            ).unparse()
                                        )
                                    )
                        case _:
                            continue
            else:
                raise ValueError(f"Extensionを処理できません。 名前：{content.__class__.__name__}")
        print(ServerHello(
            legacy_version, random,
            legacy_session_id_echo, cipher_suite,
            legacy_compression_method, server_extensions
        ))
        print(ServerHello(
            legacy_version, random,
            legacy_session_id_echo, cipher_suite,
            legacy_compression_method, server_extensions
        ).unparse().hex())
        return ServerHello(
            legacy_version, random,
            legacy_session_id_echo, cipher_suite,
            legacy_compression_method, server_extensions
        )

    def make_encrypted_extensions(self):
        ee = EncryptedExtensions([])
        return self.encrypt_handshake(ee)

    def check_client_finished(self, verify_data: bytes):
        assert len(verify_data) == 32
        finished_key = TLSKey.HKDF_Expand_Label(self.__key.client_handshake_traffic_secret,
                                                b"finished", b"", 32)
        actual_verify_data = TLSKey.HMAC(finished_key, self.__handshake_ctx.transcript_hash)
        assert actual_verify_data == verify_data

    def make_finished(self):
        self.__key.seq_upd_server()
        finished_key = TLSKey.HKDF_Expand_Label(self.__key.server_handshake_traffic_secret,
                                                b"finished", b"", 32)
        verify_data = TLSKey.HMAC(finished_key, self.__handshake_ctx.transcript_hash)
        finished = Finished(verify_data)
        return self.encrypt_handshake(finished)

    def encrypt_handshake(self, obj) -> TLSCiphertext:
        # Refer: RFC8446 §5.2 "length: The length ..."
        # Refer: https://tex2e.github.io/rfc-translater/html/rfc5116.html#2-1--Authenticated-Encryption
        self.__handshake_ctx.append(obj)
        handshake = Handshake.make(obj)
        tls_inner_plaintext = TLSInnerPlaintext(handshake.unparse(), ContentType.handshake, b"")
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
        return tls_ciphertext

    def make_certificate(self) -> TLSCiphertext:
        self.__key.seq_upd_server()
        cert = TLSKey.load_x509_cert("temp/cert.pem")
        cert = cert.public_bytes(Encoding.DER)
        certificate = Certificate.make(cert, [])
        return self.encrypt_handshake(certificate)

    def make_certificate_verify(self) -> TLSCiphertext:
        self.__key.seq_upd_server()
        algorithm = SignatureScheme.ecdsa_secp256r1_sha256
        signature_content = self.__handshake_ctx.transcript_hash
        signature_content = (  # refer: TLS8446 §4.4.3
            b"\x20" * 64 +
            b"TLS 1.3, server CertificateVerify" +
            b"\x00" +
            signature_content
        )
        encoded = hashlib.sha256(signature_content).digest()
        key = TLSKey.load_x509_key("temp/key.pem")
        priv_key = ECPrivateKey(key.private_numbers().private_value, elliptic.secp256r1)
        self.__key.ecdsa_key = priv_key
        pub_key = priv_key.public_key()
        self.__key.ecdsa_cert = pub_key

        signature = self.__key.ecdsa_key.sign(encoded)
        assert self.__key.ecdsa_cert.verify(signature, encoded)

        cv = CertificateVerify(algorithm, signature.encode())
        return self.encrypt_handshake(cv)


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
        tls_ciphertext = TLSCiphertext.from_bytes(data)
        print(tls_ciphertext)
        server.parse_application_data(tls_ciphertext.encrypted_record)
        print()
        print("------------------- Next --------------------")
        print()


if __name__ == '__main__':
    # pprint.pprint(ExtensionHeader(type=ExtensionType.ec_point_formats, content=ECPointFormats([
    #     ECPointFormat.uncompressed,
    #     ECPointFormat.ansiX962_compressed_prime,
    #     ECPointFormat.ansiX962_compressed_char2
    # ]).unparse()).unparse())
    # pprint.pprint(ExtensionHeader.from_bytes(b"\x00\x0b\x00\x04\x03\x00\x01\x02"))
    # print(ECPointFormats.from_bytes(b"\x03\x00\x01\x02"))
    main()
