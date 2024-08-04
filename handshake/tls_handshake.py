from abc import ABC, abstractmethod
from dataclasses import dataclass


__all__ = ["TLSHandshake"]


@dataclass(frozen=True)
class TLSHandshake(ABC):
    @abstractmethod
    def unparse(self):
        pass
