import enum
from http import HTTPStatus
from typing import Tuple
from flask import Blueprint, request  # type: ignore
from flask_restx import Namespace, Api, Resource  # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash  # type: ignore

from flask_authbp import user

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
class AuthImplementation(Generic[S]):
    __slots__ = ('permission_required', 'login', 'register')
    permission_required: Callable[[S], bool]
    login: Optional[Callable[[Username, Password], LoginReport[S]]]
    register: Optional[Callable[[Username, Password], RegistrationStatus]]



def auth_to_blueprint(auth: AuthImplementation[S]) -> Blueprint:
    '''
    Returns the blueprint and authorization decorator
    '''
    bp = Blueprint('auth', __name__, url_prefix='/')
    api = Api(bp)
    ns = Namespace('auth', 'Authentication and authorization', path='/')
    api.add_namespace(ns)

    if auth.registration:
        add_register_route(ns, auth.register.user_exists, auth.register.store_user)
    if auth.login:
        add_login_route(ns, auth.login.user_exists, auth.login.find_password_hash, auth.login.generate_session_info)

    return bp, generate_permission_decorator()



    
def generate_permission_decorator(ns) -> Callable:
    def permission_required(check_permission):
        def permission_decorator(f):
            def wrapper(*args, **kwargs):
                if not check_permission():
                    ns.abort(HTTPStatus.FORBIDDEN, 'Permission not allowed')
                return f(*args, **kwargs)
            wrapper.__doc__ = f.__doc__
            wrapper.__name__ = f.__name__
            return wrapper
        return permission_decorator
    return permission_required


def add_register_route(ns, user_exists, store_user):
    @ns.route('/register')
    class Register(Resource):
        @ns.expect(ns.model('UserLogin', user.name_and_pass()), validate=True)
        @ns.response(HTTPStatus.OK, 'Success')
        @ns.response(HTTPStatus.BAD_REQUEST, ns.model('RegistrationError', user.error_msgs()))
        def post(self):
            username = ns.payload['username']
            password = ns.payload['password']
            if not user.name_valid(username):
                ns.abort(HTTPStatus.BAD_REQUEST, RegistrationStatus.InvalidUsername)

            if not user.pass_valid(password):
                ns.abort(HTTPStatus.BAD_REQUEST, RegistrationStatus.InvalidPassword)

            if user_exists(username):
                ns.abort(HTTPStatus.BAD_REQUEST, RegistrationStatus.UserExists)

            store_user(username, generate_password_hash(password))

            return HTTPStatus.OK


def add_login_route(ns, user_exists, find_password_hash, generate_session_info):
    @ns.route('/login')
    class Login(Resource):
        @ns.expect(ns.model('UserLogin', user.name_and_pass()))
        @ns.response(200, 'Success')
        @ns.response(401, 'Incorrect username or password')
        def post(self):
            username = ns.payload['username']
            if not user_exists(username):
                ns.abort(HTTPStatus.UNAUTHORIZED, 'Wrong username')

            passwordHash = find_password_hash(username)
            if check_password_hash(passwordHash, ns.payload['password']):
                generate_session_info()
            else:
                ns.abort(HTTPStatus.UNAUTHORIZED, 'Wrong password')
