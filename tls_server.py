# -*- coding: UTF-8 -*-
import hashlib
import secrets
import socket

import hexdump
from Crypto.Util.number import long_to_bytes
from cryptography.hazmat.primitives._serialization import Encoding

from alert import Alert
from alert.alert import AlertDescription, AlertLevel
from common import (ContentType, ExtensionType, HandshakeType, NamedGroup,
                    SignatureScheme, ProtocolVersion)
from crypto import HandshakeContext, TLSKey, elliptic, SessionTicket
from crypto.elliptic import ECPrivateKey
from extension.ec_point_formats import ECPointFormat
from extension.extension_parser import ExtensionHeader, extensions
from extension.key_share import (KeyShareClientHello, KeyShareEntry,
                                 KeyShareServerHello)
from extension.pre_shared_key import PreSharedKeyServerHello
from extension.psk_key_exchange_modes import PskKeyExchangeMode
from extension.supported_versions import SupportedVersionsServerHello
from handshake import (CipherSuite, ClientHello, EncryptedExtensions,
                       Handshake, ServerHello)
from handshake.certificate import Certificate
from handshake.certificate_verify import CertificateVerify
from handshake.finished import Finished
from handshake.new_session_ticket import NewSessionTicket
from reader import StreamReader
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
        self.__session_ticket = SessionTicket()
        self.__psk = None
        self.__handshake_ctx = HandshakeContext([])
        self.handshake_finished = False
        self.__close = False

    # def accept_and_recv(self):
    #     conn, addr = self.__sock.accept()
    #     self.__conn = conn
    #     print(f"接続：{addr}")
    #     data = self.__conn.recv(65565)
    #     return data

    # def send(self, data: bytes):
    #     self.__sock.sendall(data)

    # def recv(self):
    #     data = self.__conn.recv(65565)
    #     return data

    def serve(self):
        print("接続を待っています…")

        while True:
            sock, addr = self.__sock.accept()
            sr = StreamReader(sock)

            with sock:
                while True:
                    if self.__close:
                        print("接続を終了します。")
                        self.reset()
                        break

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

                                        # make Server Hello
                                        sh = self.make_server_hello(ch)
                                        self.__handshake_ctx.append(sh)
                                        handshake = Handshake.make(sh)
                                        server_hello = TLSPlaintext.make(handshake)
                                        data = server_hello.unparse()
                                        print(f"<= Handshake, Server Hello ({len(data)} bytes)")
                                        hexdump.hexdump(data)

                                        self.__key.derive_secrets(self.__psk, ch, sh)
                                        ee = self.make_encrypted_extensions()
                                        ee = ee.unparse()
                                        print(f"<= Encrypted Extensions ({len(ee)} bytes) (Encrypted)")
                                        hexdump.hexdump(ee)
                                        data += ee

                                        if not self.__psk:
                                            # make certificate
                                            certificate = self.make_certificate()
                                            certificate = certificate.unparse()
                                            print(f"<= Certificate ({len(certificate)} bytes) (Encrypted)")
                                            hexdump.hexdump(certificate)
                                            data += certificate

                                            # make certificate_verify
                                            cv = self.make_certificate_verify()
                                            cv = cv.unparse()
                                            print(f"<= Certificate Verify ({len(cv)} bytes) (Encrypted)")
                                            hexdump.hexdump(cv)
                                            data += cv

                                        # make finished
                                        finished = self.make_finished()
                                        finished = finished.unparse()
                                        print(f"<= Finished ({len(finished)} bytes) (Encrypted)")
                                        hexdump.hexdump(finished)
                                        data += finished

                                        sock.sendall(data)
                            case ContentType.alert:
                                data = sr.read(length)
                                alert = Alert.from_bytes(data)
                                match alert.description:
                                    case AlertDescription.unexpected_message | AlertDescription.bad_record_mac \
                                         | AlertDescription.record_overflow | AlertDescription.handshake_failure \
                                         | AlertDescription.bad_certificate | AlertDescription.unsupported_certificate \
                                         | AlertDescription.certificate_revoked | AlertDescription.certificate_expired \
                                         | AlertDescription.certificate_unknown | AlertDescription.illegal_parameter \
                                         | AlertDescription.unknown_ca | AlertDescription.access_denied \
                                         | AlertDescription.decode_error | AlertDescription.decrypt_error \
                                         | AlertDescription.protocol_version | AlertDescription.insufficient_security \
                                         | AlertDescription.internal_error | AlertDescription.inappropriate_fallback \
                                         | AlertDescription.missing_extension | AlertDescription.unsupported_extension \
                                         | AlertDescription.unrecognized_name | AlertDescription.bad_certificate_status_response \
                                         | AlertDescription.unknown_psk_identity | AlertDescription.certificate_required \
                                         | AlertDescription.no_application_protocol:
                                        print(f"=> Alert (ERROR), {alert.description.name} ({length} bytes)")
                                        hexdump.hexdump(data)

                                        self.__close = True
                            case ContentType.change_cipher_spec:
                                print(f"=> Change Cipher Spec ({length} bytes)")
                                data = sr.read(length)
                                hexdump.hexdump(data)

                                print("this server will ignore this.")
                            case ContentType.application_data:
                                print(f"=> Application Data ({length} bytes)")
                                data = sr.read(length)
                                hexdump.hexdump(data)

                                decrypted, valid = self.__key.decrypt_handshake(data, ContentType.application_data, 0x0303, length)

                                if not valid:
                                    # alert を送信
                                    print("INVALID TAG!")
                                    alert = Alert(AlertLevel.fatal, AlertDescription.bad_record_mac).unparse()
                                    alert = TLSPlaintext(ContentType.alert, 0x0303, len(alert), alert).unparse()
                                    sock.sendall(alert)
                                    continue

                                tls_inner_plaintext = TLSInnerPlaintext.from_bytes(decrypted)
                                handshake = Handshake.from_bytes(tls_inner_plaintext.content)
                                self.check_client_finished(handshake.msg)
                                self.handshake_finished = True
                                self.__key.make_application_key(self.__handshake_ctx.handshakes, Finished(handshake.msg))

                                # New Session Ticket の送信
                                self.send_new_session_ticket(sock)
                            case _:
                                # fix: alert を送信する
                                continue
                    else:
                        # 暗号化された Record 層の処理
                        content_type = ContentType(sr.read_int(1))
                        assert content_type == ContentType.application_data

                        legacy_record_version = sr.read_int(2)
                        # assert legacy_record_version == 0x0303

                        length = sr.read_int(2)

                        data = sr.read(length)
                        received = self.parse_application_data(data, sock)

                        if received:
                            print(f"{received.decode()}")
                            self.send_application_data(received, sock)

    def reset(self):
        self.handshake_finished = False
        self.__close = False
        self.__handshake_ctx = HandshakeContext([])
        self.__key = TLSKey()

    def parse_application_data(self, data: bytes, sock) -> bytes | None:
        decrypted, valid = self.__key.decrypt_application_data(data, ContentType.application_data,
                                                        0x0303, len(data))
        if not valid:
            print("INVALID TAG!")
            alert = Alert(AlertLevel.fatal, AlertDescription.bad_record_mac)
            tls_inner_plaintext = TLSInnerPlaintext(alert.unparse(), ContentType.alert, b"")
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
            self.__close = True
            return None

        tls_inner_plaintext = TLSInnerPlaintext.from_bytes(decrypted)
        match tls_inner_plaintext.type:
            case ContentType.application_data:
                print("=> Application Data (Encrypted)")
                hexdump.hexdump(tls_inner_plaintext.content)
                return tls_inner_plaintext.content
            case ContentType.alert:
                alert = Alert.from_bytes(tls_inner_plaintext.content)
                # Refer: RFC8446 §6.2
                match alert.description:
                    case AlertDescription.close_notify:
                        print(f"=> Alert, {alert.description.name} (Encrypted)")
                        hexdump.hexdump(tls_inner_plaintext.content)

                        close_notify = Alert(AlertLevel.warning, AlertDescription.close_notify)
                        self.send_application_data(close_notify.unparse(), sock)
                        self.__close = True
                        return None
                    case AlertDescription.unexpected_message | AlertDescription.bad_record_mac \
                         | AlertDescription.record_overflow | AlertDescription.handshake_failure \
                         | AlertDescription.bad_certificate | AlertDescription.unsupported_certificate \
                         | AlertDescription.certificate_revoked | AlertDescription.certificate_expired \
                         | AlertDescription.certificate_unknown | AlertDescription.illegal_parameter \
                         | AlertDescription.unknown_ca | AlertDescription.access_denied \
                         | AlertDescription.decode_error | AlertDescription.decrypt_error \
                         | AlertDescription.protocol_version | AlertDescription.insufficient_security \
                         | AlertDescription.internal_error | AlertDescription.inappropriate_fallback \
                         | AlertDescription.missing_extension | AlertDescription.unsupported_extension \
                         | AlertDescription.unrecognized_name | AlertDescription.bad_certificate_status_response \
                         | AlertDescription.unknown_psk_identity | AlertDescription.certificate_required \
                         | AlertDescription.no_application_protocol:
                        print(f"=> Alert (ERROR), {alert.description.name} (Encrypted)")
                        hexdump.hexdump(tls_inner_plaintext.content)

                        self.__close = True
                        return None
                    case _:
                        # その他のアラートを無視
                        return None
            case _:
                # fix: alert の送信
                return None

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

    def send_new_session_ticket(self, sock):
        ticket_nonce = long_to_bytes(secrets.randbits(32))
        psk = self.__key.make_psk(ticket_nonce)
        ticket = self.__session_ticket.create_ticket(psk)
        nst = NewSessionTicket(
            86400,
            secrets.randbits(32),
            ticket_nonce,
            ticket,
            [],
        )

        handshake = Handshake.make(nst)
        data = handshake.unparse()
        tls_inner_plaintext = TLSInnerPlaintext(data, ContentType.handshake, b"")
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

    def make_server_hello(self, client_hello: ClientHello) -> ServerHello:
        legacy_version = 0x0303
        random = secrets.token_bytes(32)
        legacy_session_id_echo = client_hello.legacy_session_id

        # TLS_AES_128_GCM_SHA256 を選択
        assert CipherSuite.TLS_AES_128_GCM_SHA256 in client_hello.cipher_suites
        cipher_suite = CipherSuite.TLS_AES_128_GCM_SHA256
        legacy_compression_method = 0

        # extensions の作成
        server_extensions = []
        for ext in client_hello.extensions:
            if ext.type in extensions.keys():
                content = extensions[ext.type].from_bytes(ext.content, **{"handshake_type": HandshakeType.client_hello})
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
                        assert content.ke_modes == PskKeyExchangeMode.psk_dhe_ke
                    case ExtensionType.signature_algorithms:
                        assert SignatureScheme.ecdsa_secp256r1_sha256 in content.supported_signature_algorithms
                    case ExtensionType.ec_point_formats:
                        assert ECPointFormat.uncompressed in content.ec_point_formats
                    case ExtensionType.key_share:
                        con = KeyShareClientHello.from_bytes(ext.content)
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
                    case ExtensionType.supported_groups:
                        assert NamedGroup.x25519 in content.named_group_list
                    case ExtensionType.encrypt_then_mac:
                        # TLS 1.3 では無視する。
                        continue
                    case ExtensionType.extended_master_secret:
                        # TLS 1.3 では無視する。
                        continue
                    case ExtensionType.session_ticket:
                        # TODO: 実装
                        continue
                    case ExtensionType.key_share:
                        # TODO: 実装
                        continue
                    case ExtensionType.pre_shared_key:
                        server_extensions.append(
                            ExtensionHeader(
                                ExtensionType.pre_shared_key,
                                PreSharedKeyServerHello(
                                    selected_identity=0,
                                ).unparse()
                            )
                        )
                        # TODO: binder 値の検証
                        # ticket の検証と psk の復号
                        psk = self.__session_ticket.decrypt_psk(content.identities[0].identity)
                        self.__psk = psk
                    case _:
                        print(ExtensionType(ext.type).name)
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
        signature_content = (  # refer: RFC8446 §4.4.3
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
    server.serve()

if __name__ == '__main__':
    main()
