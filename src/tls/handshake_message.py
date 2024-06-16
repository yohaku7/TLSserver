# -*- coding: UTF-8 -*-
from abc import ABCMeta, abstractmethod


class HandshakeMessage(metaclass=ABCMeta):
    @staticmethod
    @abstractmethod
    def parse(byte_seq: bytes):
        pass
