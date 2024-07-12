# -*- coding: UTF-8 -*-
import socket

import pprint
from record import ContentType, TLSPlaintext
from handshake import Handshake
from alert import Alert
from handshake.server_hello import ServerHello
from common import HandshakeType


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

    @staticmethod
    def parse(byte_seq: bytes) -> (TLSPlaintext, Handshake):
        tp: TLSPlaintext
        tp, rest = TLSPlaintext.parse(byte_seq)
        print("--- TLSPlaintext ---")
        print(f"type: {tp.type.name} ({tp.type.value})")
        print(f"legacy_record_version: {tp.legacy_record_version}")
        print(f"length: {tp.length} [{"Verified" if tp.length == len(rest) else "Invalid"}]")
        print()
        match tp.type:
            case ContentType.handshake:
                handshake, rest = Handshake.parse(rest)
            case _:
                raise ValueError("ハンドシェイク以外にはまだ対応してないよ！")
        print(f"--- Handshake ---")
        print(f"length: {handshake.length}")
        print(f"content: {handshake.message}")
        return tp, handshake


if __name__ == '__main__':
    server = TLSServer()
    data = server.accept_and_recv()
    # data = bytes.fromhex("16030100c4010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001")
    while True:
        tp = TLSPlaintext.parse(data)
        print("----- TLSPlaintext -----")
        pprint.pprint(tp)
        match tp.type:
            case ContentType.handshake:
                match tp.fragment.msg_type:
                    case HandshakeType.client_hello:
                        server_hello = ServerHello.make(tp.fragment.message)
                        record = TLSPlaintext.make(ContentType.handshake, server_hello)
                        pprint.pprint(record)
                        print(record.unparse().hex())
                        server.send(record.unparse())
            case ContentType.alert:
                print("----- Alert -----")
                pprint.pprint(tp.fragment)
                break
        # match tp.type:
        #     case ContentType.handshake:
        #         handshake = Handshake.parse(tp.fragment)
        #         print("----- Handshake -----")
        #         pprint.pprint(handshake)
        #         match handshake.msg_type:
        #             case HandshakeType.client_hello:
        #                 sh = ServerHello.make(handshake.message)
        #                 pprint.pprint(sh)
        #                 hs = Handshake.make(HandshakeType.server_hello, sh)
        #                 record = TLSPlaintext(
        #                     type=ContentType.handshake,
        #                     legacy_record_version=0x0303,
        #                     length=len(hs),
        #                     fragment=hs,
        #                 )
        #                 print("----- Send Message -----")
        #                 pprint.pprint(record)
        #                 server.send(record.unparse())
        #     case ContentType.alert:
        #         alert = Alert.parse(tp.fragment)
        #         print("----- Alert -----")
        #         pprint.pprint(alert)
        #         break
        #     case _:
        #         raise ValueError("対応してないContentTypeだよ！")
        print()
        print("------------------- Next --------------------")
        print()
        data = server.recv()
