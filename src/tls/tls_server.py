# -*- coding: UTF-8 -*-
import socket


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 8080))
    sock.listen(1)
    conn, addr = sock.accept()
    print(f"接続：{addr}")
    print(conn.recv(65565))
    sock.close()


if __name__ == '__main__':
    main()
