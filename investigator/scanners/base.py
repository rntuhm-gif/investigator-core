from abc import ABC, abstractmethod


class BaseScanner(ABC):
    @abstractmethod
    def scan(self, target, **kwargs):
        ...

    @abstractmethod
    def summarize(self, results):
        ...

