# -*- coding: UTF-8 -*-
import hashlib
import secrets
import socket

import hexdump
from cryptography.hazmat.primitives._serialization import Encoding

from alert import Alert
from alert.alert import AlertDescription, AlertLevel
from common import (ContentType, ExtensionType, HandshakeType, NamedGroup,
                    SignatureScheme, ProtocolVersion)
from crypto import HandshakeContext, TLSKey, elliptic
from crypto.elliptic import ECPrivateKey
from extension.extension_parser import ExtensionHeader, extensions
from extension.key_share import (KeyShareClientHello, KeyShareEntry,
                                 KeyShareServerHello)
from extension.psk_key_exchange_modes import PskKeyExchangeMode
from extension.supported_versions import SupportedVersionsServerHello
from handshake import (CipherSuite, ClientHello, EncryptedExtensions,
                       Handshake, ServerHello)
from handshake.certificate import Certificate
from handshake.certificate_verify import CertificateVerify
from handshake.finished import Finished
from reader import Block, Blocks, BytesReader, StreamReader
from record import TLSCiphertext, TLSPlaintext
from record.tls_inner_plaintext import TLSInnerPlaintext


class TLSServer:
    def __init__(self, dst: str = "localhost", ip: int = 8080):
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 接続の高速化
        self.__sock.bind((dst, ip))
        self.__sock.listen(1)
        self.__conn = None
        self.__key = TLSKey()
        self.__handshake_ctx = HandshakeContext([])
        self.handshake_finished = False

    def close(self):
        self.__sock.close()

    def accept_and_recv(self):
        conn, addr = self.__sock.accept()
        self.__conn = conn
        print(f"接続：{addr}")
        data = self.__conn.recv(65565)
        return data

    def send(self, data: bytes):
        self.__sock.sendall(data)

    def recv(self):
        data = self.__conn.recv(65565)
        return data

    def parse_stream(self):
        sock, addr = self.__sock.accept()
        sr = StreamReader(sock)

        while True:
            if not self.handshake_finished:
                # 暗号化されていない Record 層の処理
                content_type = ContentType(sr.read_int(1))
                legacy_record_version = sr.read_int(2)
                length = sr.read_int(2)

                # 高レベルのプロトコルの処理
                match content_type:
                    case ContentType.handshake:
                        # Handshake の処理
                        msg_type = HandshakeType(sr.read_int(1))
                        length = sr.read_int(3)
                        data = sr.read(length)
                        match msg_type:
                            case HandshakeType.client_hello:
                                print(f"=> Handshake, Client Hello ({length} bytes)")
                                hexdump.hexdump(data)

                                ch: ClientHello = ClientHello.from_bytes(data)
                                self.__handshake_ctx.append(ch)

                                data = b""

                                sh = self.make_server_hello(ch)
                                self.__handshake_ctx.append(sh)
                                handshake = Handshake.make(sh)
                                new_tls_plaintext = TLSPlaintext.make(handshake)
                                data += TLSPlaintext.unparse(new_tls_plaintext)

                                # make encrypted_extensions
                                self.__key.derive_secrets(None, ch, sh)
                                ee = self.make_encrypted_extensions()
                                data += TLSCiphertext.unparse(ee)
                                self.__key.seq_upd_server()

                                # make certificate
                                certificate = self.make_certificate()
                                data += TLSCiphertext.unparse(certificate)
                                self.__key.seq_upd_server()

                                # make certificate_verify
                                cv = self.make_certificate_verify()
                                data += TLSCiphertext.unparse(cv)
                                self.__key.seq_upd_server()

                                # make finished
                                finished = self.make_finished()
                                data += TLSCiphertext.unparse(finished)
                                self.__key.seq_upd_server()

                                sock.sendall(data)
                    case ContentType.alert:
                        print(f"=> Alert ({length} bytes)")
                        data = sr.read(length)
                        alert = Alert.from_bytes(data)
                        print(alert)
                        print("Exit.")
                        exit(1)
                    case ContentType.change_cipher_spec:
                        print(f"=> Change Cipher Spec ({length} bytes)")
                        data = sr.read(length)
                        hexdump.hexdump(data)
                        print("this server will ignore this.")
                    case ContentType.application_data:
                        print(f"=> Application Data ({length} bytes)")
                        data = sr.read(length)
                        hexdump.hexdump(data)
                        decrypted = self.__key.decrypt_handshake(data, ContentType.application_data, 0x0303, length)
                        tls_inner_plaintext = TLSInnerPlaintext.from_bytes(decrypted)
                        handshake = Handshake.from_bytes(tls_inner_plaintext.content)
                        self.check_client_finished(handshake.msg)
                        self.handshake_finished = True
                        self.__key.make_application_key(self.__handshake_ctx.handshakes, Finished(handshake.msg))
                    case _:
                        raise ValueError
            else:
                # 暗号化された Record 層の処理
                content_type = ContentType(sr.read_int(1))
                assert content_type == ContentType.application_data

                legacy_record_version = sr.read_int(2)
                assert legacy_record_version == 0x0303

                length = sr.read_int(2)

                data = sr.read(length)
                hexdump.hexdump(data)
                received = self.parse_application_data(data, sock)

                if received:
                    print(f"受信: {received.decode()}")
                    self.send_application_data(received, sock)

                print()
                print("------------------- Next --------------------")
                print()

    def reset(self):
        self.handshake_finished = False
        self.__handshake_ctx = HandshakeContext([])
        self.__key = TLSKey()

    def parse(self, data: bytes):
        br = BytesReader(data)
        content_type, lrv, length = Blocks([
            Block(1, "int", after_parse=ContentType),
            Block(2, "int"),
            Block(2, "int"),
        ]).parse(br)
        read_data = br.read_byte(length, "raw")

        # hexdump.hexdump(read_data)

        match content_type:
            case ContentType.handshake:
                handshake: Handshake = Handshake.from_bytes(read_data)
                match handshake.msg_type:
                    case HandshakeType.client_hello:
                        self.parse_client_hello()
            case ContentType.alert:
                print(": Alert")
                alert = Alert.from_bytes(read_data)
                print(alert)
                print("Exit.")
                exit(1)
            case ContentType.change_cipher_spec:
                print("ChangeCipherSpec, ignore.")
            case ContentType.application_data:
                assert length == len(read_data)
                decrypted = self.__key.decrypt_handshake(read_data, ContentType.application_data, 0x0303, length)
                tls_inner_plaintext = TLSInnerPlaintext.from_bytes(decrypted)
                handshake = Handshake.from_bytes(tls_inner_plaintext.content)
                self.check_client_finished(handshake.msg)
                self.handshake_finished = True
                self.__key.make_application_key(self.__handshake_ctx.handshakes, Finished(handshake.msg))
            case _:
                raise ValueError

        if br.rest_length != 0:
            self.parse(br.rest_bytes())

    def parse_application_data(self, data: bytes, sock) -> bytes:
        decrypted = self.__key.decrypt_application_data(data, ContentType.application_data,
                                                        0x0303, len(data))
        tls_inner_plaintext = TLSInnerPlaintext.from_bytes(decrypted)
        match tls_inner_plaintext.type:
            case ContentType.application_data:
                print("=> Application Data (Encrypted)")
                return tls_inner_plaintext.content
            case ContentType.alert:
                print("=> Alert (Encrypted)")
                hexdump.hexdump(tls_inner_plaintext.content)
                alert = Alert.from_bytes(tls_inner_plaintext.content)
                if alert.description == AlertDescription.close_notify:
                    close_notify = Alert(AlertLevel.warning, AlertDescription.close_notify)
                    self.send_application_data(close_notify.unparse(), sock)
                    print("接続終了。")
                else:
                    print("Exit.")
                    exit(1)
        self.__key.seq_upd_server()

    def send_application_data(self, data: bytes, sock):
        tls_inner_plaintext = TLSInnerPlaintext(data, ContentType.application_data, b"")
        tls_ciphertext_len = len(tls_inner_plaintext.unparse()) + 16
        encrypted, tag = self.__key.encrypt_application_data(tls_inner_plaintext.unparse(),
                                                             ContentType.application_data,
                                                             0x0303,
                                                             tls_ciphertext_len)
        encrypted += tag
        tls_ciphertext = TLSCiphertext(
            ContentType.application_data, 0x0303, len(encrypted),
            encrypted
        )
        sock.send(tls_ciphertext.unparse())
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
                    if reply.obj is not None:
                        server_extensions.append(reply.obj)
                    else:
                        raise ValueError
                except:
                    match ext.type:
                        case ExtensionType.supported_versions:
                            assert ProtocolVersion.TLS_1_3 in content.version
                            server_extensions.append(
                                ExtensionHeader(
                                    ExtensionType.supported_versions,
                                    SupportedVersionsServerHello(ProtocolVersion.TLS_1_3).unparse()
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
                                    print(con.client_shares)
                                    self.__key.exchange_key_x25519(con.client_shares[0])
                                    server_extensions.append(
                                        ExtensionHeader(
                                            ExtensionType.key_share,
                                            KeyShareServerHello(
                                                server_share=KeyShareEntry(
                                                    group=NamedGroup.x25519,
                                                    key_exchange=self.__key.x25519.public_key.encode()
                                                )
                                            ).unparse()
                                        )
                                    )
                        case _:
                            continue
            else:
                print(f"Extensionを処理できません。{ext}")
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
        cert = TLSKey.load_x509_cert("temp/cert.pem")
        cert = cert.public_bytes(Encoding.DER)
        certificate = Certificate.make(cert, [])
        return self.encrypt_handshake(certificate)

    def make_certificate_verify(self) -> TLSCiphertext:
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
    server = TLSServer(ip=4433)
    while True:
        try:
            server.parse_stream()
        except EOFError:
            server.reset()
            continue

if __name__ == '__main__':
    main()
