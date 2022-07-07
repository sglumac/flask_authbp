from dataclasses import dataclass
from enum import Enum
from typing import Callable, Generic, Optional, Type, TypeVar


class RegistrationStatus(Enum):
    InvalidUsername = 'Invalid username'
    InvalidPassword = 'Invalid password'
    UserExists = 'Username already exists'
    Succcess = 'Success'


class LoginStatus(Enum):
    NonExistingUsername = 'Username does not exist'
    WrongPassword = 'Invalid password'
    Success = 'Success'


S = TypeVar('S')

@dataclass
class LoginReport(Generic[S]):
    __slots__ = ('status', 'session')
    status: LoginStatus
    session: Optional[S]


Username = str
Password = str

@dataclass
class Auth(Generic[S]):
    __slots__ = ('permission_required', 'login', 'register')
    permission_required: Callable[[S], bool]
    login: Optional[Callable[[Username, Password], LoginReport[S]]]
    regiter: Optional[Callable[[Username, Password], RegistrationStatus]]
