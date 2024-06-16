# -*- coding: UTF-8 -*-
# 標準パッケージsocketの簡易的なラッパー。
# @author yohaku7

import socket


class IPv4BasicSocket:
    def __init__(self, dst: str = "localhost", port: int = 8080, timeout: int = 60):
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__sock.settimeout(timeout)
        self.__sock.bind((dst, port))

    def __del__(self):
        self.close()

    def close(self):
        self.__sock.close()

    def listen(self):
        self.__sock.listen(1)

    def recv(self, bufsize: int = 65565) -> bytes:
        self.__sock.listen(1)
        conn, addr = self.__sock.accept()
        res = conn.recv(bufsize)
        conn.close()
        return res


if __name__ == '__main__':
    s = IPv4BasicSocket()
    while True:
        s.listen()
