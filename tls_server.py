# -*- coding: UTF-8 -*-
import asyncio
import hashlib
import secrets
import socket
from enum import Enum, auto

import hexdump
from Crypto.Util.number import long_to_bytes
from cryptography.hazmat.primitives._serialization import Encoding

from alert import Alert
from alert.alert import AlertDescription, AlertLevel
from common import (ContentType, ExtensionType, HandshakeType, NamedGroup,
                    SignatureScheme, ProtocolVersion)
from crypto import TLSKey, elliptic, SessionTicket
from crypto.elliptic import ECPrivateKey
from crypto.tls_key import TLSConnectionKey, HKDF
from extension.early_data import EarlyDataIndicationNewSessionTicket, EarlyDataIndicationEncryptedExtensions
from extension.ec_point_formats import ECPointFormat
from extension.extension_parser import ExtensionHeader, extensions
from extension.key_share import (KeyShareEntry,
                                 KeyShareServerHello)
from extension.pre_shared_key import PreSharedKeyServerHello
from extension.psk_key_exchange_modes import PskKeyExchangeMode
from extension.supported_versions import SupportedVersionsServerHello
from handshake import (CipherSuite, EncryptedExtensions)
from handshake.certificate import Certificate
from handshake.certificate_verify import CertificateVerify
from handshake.client_hello import TLSClientHello
from handshake.finished import Finished
from handshake.handshake import TLSHandshake
from handshake.new_session_ticket import NewSessionTicket
from handshake.server_hello import TLSServerHello
from reader import StreamReader, BytesReader
from reader.validation_result import ValidationResult
from record import TLSCiphertext, TLSPlaintext
from record.tls_inner_plaintext import TLSInnerPlaintext
from record.tls_record import TLSRecordHeader


class TLSServerConnectionState(Enum):
    # refer: RFC8446 Appendix A.2
    START = auto()
    RECVD_CH = auto()
    NEGOTIATED = auto()
    WAIT_EOED = auto()
    WAIT_FLIGHT2 = auto()
    WAIT_CERT = auto()
    WAIT_CV = auto()
    WAIT_FINISHED = auto()
    CONNECTED = auto()

    CLOSED = auto()
    ERROR = auto()


class TLSServerConnection:
    def __init__(self, sock: socket.socket, session_ticket: SessionTicket):
        self.__connection_key = TLSConnectionKey()
        self.__reader = StreamReader(sock)
        self.__sock = sock
        self.__state = TLSServerConnectionState.START

        self.__session_ticket = session_ticket

        self.__early_data_exist = False

        self.__client_hello: TLSClientHello | None = None
        self.__server_hello: TLSServerHello | None = None
        self.__end_of_early_data: bytes | None = None

    def _process(self):
        self._process_start()

        if self.__state == TLSServerConnectionState.ERROR:
            self.__sock.close()
            return
        assert self.__state == TLSServerConnectionState.RECVD_CH
        self._process_recvd_ch()

        if self.__state == TLSServerConnectionState.ERROR:
            self.__sock.close()
            return
        assert self.__state == TLSServerConnectionState.NEGOTIATED
        self._process_negotiated()

        if self.__state == TLSServerConnectionState.ERROR:
            self.__sock.close()
            return
        elif self.__state == TLSServerConnectionState.WAIT_EOED:
            self._process_wait_eoed()

        assert self.__state == TLSServerConnectionState.WAIT_FLIGHT2
        self._process_wait_flight2()

        if self.__state == TLSServerConnectionState.WAIT_CERT:
            self._process_wait_cert()

            assert self.__state == TLSServerConnectionState.WAIT_CV
            self._process_wait_cv()

        assert self.__state == TLSServerConnectionState.WAIT_FINISHED
        self._process_wait_finished()

        assert self.__state == TLSServerConnectionState.CONNECTED
        self._process_connected()

        assert self.__state == TLSServerConnectionState.CLOSED
        self.__sock.close()

    def _process_start(self):
        # Record の受信
        data = self.__reader.read(5)
        record_header = TLSRecordHeader.from_bytes(data).validate()
        if not record_header.success:
            self.__error(record_header)
        record_header = record_header.unwrap()

        # Record の検証
        if record_header.content_type != ContentType.handshake:
            self.__error_unexpected_message()

        # Handshake の受信
        data = self.__reader.read(4)
        data += self.__reader.read(int.from_bytes(data[1:], "big"))
        handshake = TLSHandshake.from_bytes(data).validate().unwrap()

        # Handshake の検証
        if handshake.msg_type != HandshakeType.client_hello:
            self.__error_unexpected_message()

        self.__connection_key.update_transcript_hash(handshake.to_bytes())

        client_hello = TLSClientHello.from_bytes(handshake.msg).validate().unwrap()
        self.__client_hello = client_hello
        self.__state = TLSServerConnectionState.RECVD_CH

    def _process_recvd_ch(self):
        # パラメータを選択する
        # Cipher Suite
        if CipherSuite.TLS_AES_128_GCM_SHA256 not in self.__client_hello.cipher_suites:
            self.__error_illegal_parameter()

        # Extensions
        server_ext = []

        br = BytesReader(self.__client_hello.extensions)
        while br.rest_length > 0:
            tag = br.read_byte(2, "int")
            length = br.read_byte(2, "int")
            value = br.read_byte(length, "raw")

            if tag not in ExtensionType:
                self.__error_illegal_parameter()
                return

            value = extensions[tag].from_bytes(value, **{"handshake_type": HandshakeType.client_hello})
            match ExtensionType(tag):
                case ExtensionType.supported_versions:
                    if ProtocolVersion.TLS_1_3 not in value.version:
                        self.__error_illegal_parameter()
                        return
                    server_ext.append(
                        ExtensionHeader(
                            ExtensionType.supported_versions,
                            SupportedVersionsServerHello(ProtocolVersion.TLS_1_3).unparse(),
                        ).unparse()
                    )
                case ExtensionType.psk_key_exchange_modes:
                    if value.ke_modes != PskKeyExchangeMode.psk_dhe_ke:
                        self.__error_illegal_parameter()
                        return
                case ExtensionType.signature_algorithms:
                    if SignatureScheme.ecdsa_secp256r1_sha256 not in value.supported_signature_algorithms:
                        self.__error_illegal_parameter()
                        return
                case ExtensionType.ec_point_formats:
                    if ECPointFormat.uncompressed not in value.ec_point_formats:
                        self.__error_illegal_parameter()
                        return
                case ExtensionType.key_share:
                    self.__connection_key.exchange_key_x25519(value.client_shares[0])
                    server_ext.append(
                        ExtensionHeader(
                            ExtensionType.key_share,
                            KeyShareServerHello(
                                server_share=KeyShareEntry(
                                    group=NamedGroup.x25519,
                                    key_exchange=self.__connection_key.x25519.public_key.encode()
                                )
                            ).unparse()
                        ).unparse()
                    )
                case ExtensionType.supported_groups:
                    if NamedGroup.x25519 not in value.named_group_list:
                        self.__error_illegal_parameter()
                        return
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
                    server_ext.append(
                        ExtensionHeader(
                            ExtensionType.pre_shared_key,
                            PreSharedKeyServerHello(
                                selected_identity=0,
                            ).unparse()
                        ).unparse()
                    )
                    # TODO: binder 値の検証
                    # ticket の検証と psk の復号
                    psk, ticket_age_add = self.__session_ticket.decrypt_ticket(value.identities[0].identity)
                    # チケット年齢の検証
                    age = value.identities[0].obfuscated_ticket_age
                    age %= 2 ** 32
                    age -= ticket_age_add
                    print("Ticket age:", age)
                    assert age <= 86400 * 1000
                    self.__connection_key.psk = psk
                case ExtensionType.early_data:
                    self.__early_data_exist = True
                case _:
                    # 無視する
                    continue

        server_ext = b"".join([x for x in server_ext])

        server_hello = TLSServerHello(
            0x0303,
            secrets.token_bytes(32),
            self.__client_hello.legacy_session_id,
            cipher_suite=CipherSuite.TLS_AES_128_GCM_SHA256,
            legacy_compression_method=0,
            extensions=server_ext,
        )
        self.__server_hello = server_hello
        self.__state = TLSServerConnectionState.NEGOTIATED

    def _process_negotiated(self):
        # Server Hello の送信
        data = self.__server_hello.to_bytes()
        handshake = TLSHandshake(HandshakeType.server_hello, len(data), data)
        self.send_plain_record(handshake.to_bytes(), ContentType.handshake)

        # 鍵の導出
        self.__connection_key.derive_early_secrets()

        self.__connection_key.update_transcript_hash(handshake.to_bytes())
        self.__connection_key.derive_handshake_secrets()

        # Encrypted Extensions の送信
        if not self.__early_data_exist:
            enc_ext = []
        else:
            enc_ext = [
                ExtensionHeader(
                    ExtensionType.early_data,
                    EarlyDataIndicationEncryptedExtensions().unparse(),
                )
            ]
        ee = EncryptedExtensions(enc_ext).unparse()
        handshake = TLSHandshake(HandshakeType.encrypted_extensions, len(ee), ee).to_bytes()
        self.__connection_key.update_transcript_hash(handshake)
        ee_record = self.construct_encrypted_hs_record(handshake, ContentType.handshake)
        self.__sock.sendall(ee_record)

        data = b""
        if not self.__connection_key.psk:
            # make certificate
            certificate = self.make_certificate()
            print(f"<= Certificate ({len(certificate)} bytes) (Encrypted)")
            hexdump.hexdump(certificate)
            data += certificate

            # make certificate_verify
            cv = self.make_certificate_verify()
            print(f"<= Certificate Verify ({len(cv)} bytes) (Encrypted)")
            hexdump.hexdump(cv)
            data += cv

        # make finished
        finished = self.make_finished()
        print(f"<= Finished ({len(finished)} bytes) (Encrypted)")
        hexdump.hexdump(finished)
        data += finished

        self.__sock.sendall(data)

        # 0-RTT の分岐
        if self.__early_data_exist:
            self.__state = TLSServerConnectionState.WAIT_EOED
        else:
            self.__state = TLSServerConnectionState.WAIT_FLIGHT2

    def _process_wait_eoed(self):
        # EndOfEarlyData を受信するまで Early Data を受信する
        while True:
            pln = self._recv_encrypted_e_record()

            if self.__state == TLSServerConnectionState.ERROR:
                return
            if pln is None:
                continue

            if pln.type == ContentType.application_data:
                print(f"Early Data Received! {pln.content.decode()}")
            elif pln.type == ContentType.handshake:
                handshake = TLSHandshake.from_bytes(pln.content).validate().unwrap()
                if handshake.msg_type == HandshakeType.end_of_early_data:
                    self.__end_of_early_data = handshake.to_bytes()
                    print("Early Data End.")
                    break
            else:
                self.__state = TLSServerConnectionState.ERROR
                return

        self.__state = TLSServerConnectionState.WAIT_FLIGHT2

    def _process_wait_flight2(self):
        # クライアントに認証を求めない
        self.__state = TLSServerConnectionState.WAIT_FINISHED

    def _process_wait_cert(self):
        raise NotImplementedError

    def _process_wait_cv(self):
        raise NotImplementedError

    def _process_wait_finished(self):
        # Change Cipher Spec を受信する
        # fix: Change Cipher Spec が来なくてもエラーを出さないようにする
        if not self.__early_data_exist:
            self._recv_encrypted_hs_record()

        # application 鍵の導出
        self.__connection_key.derive_application_secrets()

        # EndOfEarlyData を Transcript Hash に含める
        if self.__end_of_early_data:
            self.__connection_key.update_transcript_hash(self.__end_of_early_data)

        # Client Finished を受信する
        tls_inner_plaintext = self._recv_encrypted_hs_record()
        handshake = TLSHandshake.from_bytes(tls_inner_plaintext.content)
        self.check_client_finished(handshake.msg)

        # resumption 鍵の導出
        self.__connection_key.update_transcript_hash(handshake.to_bytes())
        self.__connection_key.derive_resumption_secret()

        self.__state = TLSServerConnectionState.CONNECTED

    def _process_connected(self):
        # Session Ticket の発行
        self.send_new_session_ticket()

        # echo するサーバ
        while True:
            pln = self._recv_encrypted_ap_record()
            if pln is None:
                return
            print(f"Received: {pln}")
            if pln.type == ContentType.alert:
                alert = Alert.from_bytes(pln.content)
                if alert.description == AlertDescription.close_notify:
                    print("Close.")
                    self.__state = TLSServerConnectionState.CLOSED
                    return
            elif pln.type == ContentType.application_data:
                self.__sock.sendall(self.construct_encrypted_ap_record(pln.content, ContentType.application_data))
            else:
                self.__state = TLSServerConnectionState.ERROR
                return

    def __error(self, validation: ValidationResult):
        self.__state = TLSServerConnectionState.ERROR
        self.send_plain_alert(validation.alert)

    def __error_unexpected_message(self):
        self.__state = TLSServerConnectionState.ERROR
        self.send_plain_alert(
            Alert(AlertLevel.fatal, AlertDescription.unexpected_message)
        )

    def __error_illegal_parameter(self):
        self.__state = TLSServerConnectionState.ERROR
        self.send_plain_alert(
            Alert(AlertLevel.fatal, AlertDescription.illegal_parameter)
        )

    def _recv_encrypted_hs_record(self) -> TLSInnerPlaintext | None:
        header = self.__reader.read(5)
        header = TLSRecordHeader.from_bytes(header).validate().unwrap()
        data = self.__reader.read(header.length)

        if header.content_type == ContentType.change_cipher_spec:
            print(f"=> Change Cipher Spec ({header.length} bytes)")
            return None
        elif header.content_type == ContentType.application_data:
            # Client Finished
            print(f"=> Application Data ({header.length} bytes)")

            decrypted, valid = self.__connection_key.decrypt_with_handshake_secret(
                data,
                header.to_bytes(),
                "client",
            )

            if not valid:
                # alert を送信
                print("[hs] INVALID TAG!")
                alert = Alert(AlertLevel.fatal, AlertDescription.bad_record_mac).unparse()
                alert = TLSPlaintext(ContentType.alert, 0x0303, len(alert), alert).unparse()
                self.__sock.sendall(alert)
                self.__state = TLSServerConnectionState.ERROR
                return None

            decrypted = TLSInnerPlaintext.from_bytes(decrypted)
            return decrypted
        else:
            self.__state = TLSServerConnectionState.ERROR
            return None

    def _recv_encrypted_ap_record(self) -> TLSInnerPlaintext | None:
        header = self.__reader.read(5)
        header = TLSRecordHeader.from_bytes(header).validate().unwrap()
        data = self.__reader.read(header.length)

        if header.content_type == ContentType.application_data:
            print(f"=> Application Data ({header.length} bytes)")

            decrypted, valid = self.__connection_key.decrypt_with_application_secret(
                data,
                header.to_bytes(),
                "client",
            )

            if not valid:
                # alert を送信
                print("[ap] INVALID TAG!")
                alert = Alert(AlertLevel.fatal, AlertDescription.bad_record_mac).unparse()
                alert = TLSPlaintext(ContentType.alert, 0x0303, len(alert), alert).unparse()
                self.__sock.sendall(alert)
                self.__state = TLSServerConnectionState.ERROR
                return None

            decrypted = TLSInnerPlaintext.from_bytes(decrypted)
            return decrypted
        else:
            self.__state = TLSServerConnectionState.ERROR
            return None

    def _recv_encrypted_e_record(self) -> TLSInnerPlaintext | None:
        header = self.__reader.read(5)
        header = TLSRecordHeader.from_bytes(header).validate().unwrap()
        data = self.__reader.read(header.length)

        if header.content_type == ContentType.application_data:
            print(f"=> Application Data (Early Data) ({header.length} bytes)")

            decrypted, valid = self.__connection_key.decrypt_with_early_secret(
                data,
                header.to_bytes(),
            )

            if not valid:
                # alert を送信
                print("[e] INVALID TAG!")
                alert = Alert(AlertLevel.fatal, AlertDescription.bad_record_mac).unparse()
                alert = TLSPlaintext(ContentType.alert, 0x0303, len(alert), alert).unparse()
                self.__sock.sendall(alert)
                self.__state = TLSServerConnectionState.ERROR
                return None

            decrypted = TLSInnerPlaintext.from_bytes(decrypted)
            return decrypted
        elif header.content_type == ContentType.change_cipher_spec:
            # 無視する
            return None
        else:
            self.__state = TLSServerConnectionState.ERROR
            return None

    def make_certificate(self) -> bytes:
        cert = TLSConnectionKey.load_x509_cert("temp/cert.pem")
        cert = cert.public_bytes(Encoding.DER)
        certificate = Certificate.make(cert, []).unparse()
        handshake = TLSHandshake(HandshakeType.certificate, len(certificate), certificate).to_bytes()
        self.__connection_key.update_transcript_hash(handshake)
        return self.construct_encrypted_hs_record(handshake, ContentType.handshake)

    def make_certificate_verify(self) -> bytes:
        algorithm = SignatureScheme.ecdsa_secp256r1_sha256
        signature_content = self.__connection_key.current_transcript_hash
        signature_content = (  # refer: RFC8446 §4.4.3
            b"\x20" * 64 +
            b"TLS 1.3, server CertificateVerify" +
            b"\x00" +
            signature_content
        )
        encoded = hashlib.sha256(signature_content).digest()
        key = TLSConnectionKey.load_x509_key("temp/key.pem")
        priv_key = ECPrivateKey(key.private_numbers().private_value, elliptic.secp256r1)
        self.__connection_key.ecdsa_key = priv_key
        pub_key = priv_key.public_key()
        self.__connection_key.ecdsa_cert = pub_key

        signature = self.__connection_key.ecdsa_key.sign(encoded)
        assert self.__connection_key.ecdsa_cert.verify(signature, encoded)

        cv = CertificateVerify(algorithm, signature.encode()).unparse()
        handshake = TLSHandshake(HandshakeType.certificate_verify, len(cv), cv).to_bytes()
        self.__connection_key.update_transcript_hash(handshake)
        return self.construct_encrypted_hs_record(handshake, ContentType.handshake)

    def make_finished(self):
        finished_key = HKDF.HKDF_Expand_Label(self.__connection_key.server_handshake_traffic_secret,
                                                b"finished", b"", 32)
        verify_data = HKDF.HMAC(finished_key, self.__connection_key.current_transcript_hash)
        finished = Finished(verify_data).unparse()
        handshake = TLSHandshake(HandshakeType.finished, len(finished), finished).to_bytes()
        self.__connection_key.update_transcript_hash(handshake)
        return self.construct_encrypted_hs_record(handshake, ContentType.handshake)

    def check_client_finished(self, verify_data: bytes):
        assert len(verify_data) == 32
        finished_key = HKDF.HKDF_Expand_Label(self.__connection_key.client_handshake_traffic_secret,
                                                b"finished", b"", 32)
        actual_verify_data = HKDF.HMAC(finished_key, self.__connection_key.current_transcript_hash)
        assert actual_verify_data == verify_data

    def send_plain_record(self, data: bytes, content_type: ContentType):
        header = TLSRecordHeader(content_type, 0x0303, len(data)).to_bytes()
        data = header + data
        self.__sock.sendall(data)

    def construct_encrypted_hs_record(self, content: bytes, content_type: ContentType):
        tls_inner_plaintext = TLSInnerPlaintext(content, content_type, b"").unparse()
        tls_ciphertext_header = TLSRecordHeader(ContentType.application_data,
                                                0x0303,
                                                len(tls_inner_plaintext) + 16).to_bytes()
        encrypted_record, tag = self.__connection_key.encrypt_with_handshake_secret(tls_inner_plaintext,
                                                                               tls_ciphertext_header,
                                                                               "server")
        encrypted_record += tag
        tls_ciphertext = TLSCiphertext(ContentType.application_data,
                                       0x0303,
                                       len(encrypted_record),
                                       encrypted_record).unparse()
        return tls_ciphertext

    def construct_encrypted_ap_record(self, content: bytes, content_type: ContentType):
        tls_inner_plaintext = TLSInnerPlaintext(content, content_type, b"").unparse()
        tls_ciphertext_header = TLSRecordHeader(ContentType.application_data,
                                                0x0303,
                                                len(tls_inner_plaintext) + 16).to_bytes()
        encrypted_record, tag = self.__connection_key.encrypt_with_application_secret(tls_inner_plaintext,
                                                                               tls_ciphertext_header,
                                                                               "server")
        encrypted_record += tag
        tls_ciphertext = TLSCiphertext(ContentType.application_data,
                                       0x0303,
                                       len(encrypted_record),
                                       encrypted_record).unparse()
        return tls_ciphertext

    def send_plain_alert(self, alert: Alert):
        data = alert.unparse()
        self.send_plain_record(data, ContentType.alert)

    def send_new_session_ticket(self):
        ticket_nonce = long_to_bytes(secrets.randbits(32))
        ticket_age_add = secrets.randbits(32)
        psk = self.__connection_key.derive_psk(ticket_nonce)
        ticket = self.__session_ticket.create_ticket(ticket_age_add, psk)
        nst = NewSessionTicket(
            86400,
            ticket_age_add,
            ticket_nonce,
            ticket,
            [
                ExtensionHeader(
                    ExtensionType.early_data,
                    EarlyDataIndicationNewSessionTicket(
                        max_early_data_size=2048,
                    ).unparse(),
                )
            ],
        ).unparse()

        handshake = TLSHandshake(HandshakeType.new_session_ticket, len(nst), nst).to_bytes()
        self.__sock.send(self.construct_encrypted_ap_record(handshake, ContentType.handshake))


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("localhost", 4433))
    server.listen()
    loop = asyncio.get_event_loop()

    session_ticket = SessionTicket()

    # server = TLSServer(ip=4433)
    # server.serve()


if __name__ == '__main__':
    main()
