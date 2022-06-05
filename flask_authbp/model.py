from typing import Protocol
from abc import abstractmethod


class Storage(Protocol):
    @abstractmethod
    def store_user(self, username, password):
        ...

    @abstractmethod
    def find_password_hash(self, username):
        ...

    @abstractmethod
    def store_refresh_token(self, username, refreshToken, userAgentHash):
        ...

    @abstractmethod
    def find_refresh_token(self, userAgentHash):
        ...

    @abstractmethod
    def update_refresh_token(self, userAgentHash, refreshToken):
        ...
