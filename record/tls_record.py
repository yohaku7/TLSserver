from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class TLSRecord(ABC):
    @staticmethod
    @abstractmethod
    def make(obj):
        pass

    @abstractmethod
    def unparse(self):
        pass
