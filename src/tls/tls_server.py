# -*- coding: UTF-8 -*-
import socket
from src.tls.client_hello import ClientHello
from src.tls.tls_plaintext import TLSPlaintext
from src.tls.handshake import Handshake


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 8080))
    sock.listen(1)
    conn, addr = sock.accept()
    print(f"接続：{addr}")
    recv_bytes = conn.recv(65565)
    tls_plaintext, rest = TLSPlaintext.parse(recv_bytes)
    assert tls_plaintext.length == len(rest)
    print(tls_plaintext)
    handshake, rest = Handshake.parse(rest)
    assert handshake.length == len(rest)
    print(handshake)
    client_hello, rest = ClientHello.parse(rest)
    print(client_hello)
    sock.close()


if __name__ == '__main__':
    main()
