# -*- coding: UTF-8 -*-
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
from crypto import HandshakeContext, TLSKey, elliptic, SessionTicket
from crypto.elliptic import ECPrivateKey
from crypto.tls_key import TLSConnectionKey
from extension.early_data import EarlyDataIndicationNewSessionTicket
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

    ERROR = auto()


class TLSServerConnection:
    def __init__(self, sock: socket.socket):
        self.__key = TLSKey()
        self.__connection_key = TLSConnectionKey()
        self.__reader = StreamReader(sock)
        self.__sock = sock
        self.__handshake_ctx = HandshakeContext([])
        self.__state = TLSServerConnectionState.START

        self.__client_hello: TLSClientHello | None = None
        self.__server_hello: TLSServerHello | None = None

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
        hexdump.hexdump(data)
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
                    self.__psk = psk
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
        self.__connection_key.update_transcript_hash(handshake.to_bytes())
        self.send_plain_record(handshake.to_bytes(), ContentType.handshake)

        # 鍵の導出
        self.__connection_key.derive_early_secrets(None)
        self.__connection_key.derive_handshake_secrets()

        print(self.__connection_key.server_handshake_traffic_secret.hex())

        # Encrypted Extensions の送信
        enc_ext = []
        ee = EncryptedExtensions(enc_ext).unparse()
        handshake = TLSHandshake(HandshakeType.encrypted_extensions, len(ee), ee).to_bytes()
        self.__connection_key.update_transcript_hash(handshake)
        ee_record = self.construct_encrypted_record(handshake, ContentType.handshake)
        self.__sock.sendall(ee_record)

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

    def send_plain_record(self, data: bytes, content_type: ContentType):
        header = TLSRecordHeader(content_type, 0x0303, len(data)).to_bytes()
        data = header + data
        hexdump.hexdump(data)
        self.__sock.sendall(data)

    def construct_encrypted_record(self, content: bytes, content_type: ContentType):
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

    def send_plain_alert(self, alert: Alert):
        data = alert.unparse()
        self.send_plain_record(data, ContentType.alert)


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
        self.__early_data_exist = False
        self.__handshake_ctx = HandshakeContext([])
        self.handshake_finished = False
        self.__close = False

    def serve(self):
        print("接続を待っています…")

        while True:
            sock, addr = self.__sock.accept()
            sr = StreamReader(sock)

            # conn = TLSServerConnection(sock)
            # conn._process()
            # return

            with sock:
                while True:
                    if self.__close:
                        print("接続を終了します。")
                        self.reset()
                        break

                    if not self.handshake_finished:
                        # 暗号化されていない Record 層の処理
                        data = sr.read(5)
                        record_header = TLSRecordHeader.from_bytes(data).validate().unwrap()
                        print(record_header)
                        content_type = record_header.content_type
                        legacy_record_version = record_header.legacy_record_version
                        length = record_header.length

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
                                # if self.__early_data_exist:
                                #     # Early Data の処理
                                #     length = sr.read_int(2)
                                #     data = sr.read(length)
                                #     received = self.parse_early_data(data, sock)
                                #
                                #     if received:
                                #         print(f"Early Data: {received.decode()}")
                                #
                                #     self.__early_data_exist = False
                                #     continue

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
                            # self.send_application_data(received, sock)

    def reset(self):
        self.handshake_finished = False
        self.__close = False
        self.__handshake_ctx = HandshakeContext([])
        self.__key = TLSKey()

    def parse_early_data(self, data: bytes, sock) -> bytes | None:
        decrypted, valid = self.__key.decrypt_early_data(data)
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
        return tls_inner_plaintext.content

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
        ticket_age_add = secrets.randbits(32)
        psk = self.__key.make_psk(ticket_nonce)
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
                        psk, ticket_age_add = self.__session_ticket.decrypt_ticket(content.identities[0].identity)
                        # チケット年齢の検証
                        age = content.identities[0].obfuscated_ticket_age
                        age %= 2 ** 32
                        age -= ticket_age_add
                        print("Ticket age:", age)
                        assert age <= 86400 * 1000
                        self.__psk = psk
                    case ExtensionType.early_data:
                        self.__early_data_exist = True
                    case _:
                        print(ExtensionType(ext.type).name)
            else:
                print(f"Extensionを処理できません。{ext}")

        return ServerHello(
            legacy_version, random,
            legacy_session_id_echo, cipher_suite,
            legacy_compression_method, server_extensions
        )

    def check_client_extension(self, ch_ext: list[ExtensionHeader]) -> list[ExtensionHeader]:
        # extensions の作成
        server_extensions = []
        for ext in ch_ext:
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
                        psk, ticket_age_add = self.__session_ticket.decrypt_ticket(content.identities[0].identity)
                        # チケット年齢の検証
                        age = content.identities[0].obfuscated_ticket_age
                        age %= 2 ** 32
                        age -= ticket_age_add
                        print("Ticket age:", age)
                        assert age <= 86400 * 1000
                        self.__psk = psk
                    case ExtensionType.early_data:
                        self.__early_data_exist = True
                    case _:
                        print(ExtensionType(ext.type).name)
            else:
                print(f"Extensionを処理できません。{ext}")
            return server_extensions

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
