# -*- coding: UTF-8 -*-
import socket
from src.tls.tls_plaintext import TLSPlaintext, ContentType
from src.tls.handshake import Handshake


class TLSServer:
    def __init__(self, dst: str = "localhost", ip: int = 8080):
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__sock.bind((dst, ip))

    def __del__(self):
        self.close()

    def close(self):
        self.__sock.close()

    def accept_and_recv(self):
        self.__sock.listen(1)
        conn, addr = self.__sock.accept()
        print(f"接続：{addr}")
        data = conn.recv(65565)
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
    print(server.parse(data))
