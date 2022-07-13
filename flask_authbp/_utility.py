from http import HTTPStatus
from flask import Blueprint, abort, redirect, request  # type: ignore
from flask_restx import Namespace, Api, Resource, fields  # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash  # type: ignore

from flask_authbp import user

from enum import Enum
from typing import Callable, Tuple

from flask_authbp.types import Authentication


class RegistrationStatus(Enum):
    InvalidUsername = 'Invalid username'
    InvalidPassword = 'Invalid password'
    UserExists = 'Username already exists'
    Succcess = 'Success'


class LoginStatus(Enum):
    NonExistingUsername = 'Username does not exist'
    WrongPassword = 'Invalid password'
    Success = 'Success'


def authentication_blueprint(authentication: Authentication) -> Tuple[Blueprint, Namespace]:
    bp = Blueprint('auth', __name__, url_prefix='/')
    api = Api(bp)
    ns = Namespace('auth', 'Authentication', path='/')
    api.add_namespace(ns)
    add_register_route(ns, authentication.find_password_hash, authentication.store_user)
    add_login_route(ns, authentication.find_password_hash, authentication.generate_session_info)
    return bp, ns


def add_register_route(ns, user_exists, store_user):
    @ns.route('/register')
    class Register(Resource):
        @ns.expect(ns.model('UserLogin', user.name_and_pass()), validate=True)
        @ns.response(HTTPStatus.OK, 'Success')
        @ns.response(HTTPStatus.BAD_REQUEST, ns.model('RegistrationError', error_msgs()))
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


def add_login_route(ns, find_password_hash, generate_session_info):
    @ns.route('/login')
    class Login(Resource):
        @ns.expect(ns.model('UserLogin', user.name_and_pass()))
        @ns.response(200, 'Success')
        @ns.response(401, 'Incorrect username or password')
        def post(self):
            username = ns.payload['username']
            passwordHash = find_password_hash(username)

            if not passwordHash:
                ns.abort(HTTPStatus.UNAUTHORIZED, 'Wrong username')

            if check_password_hash(passwordHash, ns.payload['password']):
                response = generate_session_info(username)
                if response:
                    return response
                else:
                    return HTTPStatus.OK
            else:
                ns.abort(HTTPStatus.UNAUTHORIZED, 'Wrong password')


class PermissionDecorator:
    def __init__(self, get_user):
        self._get_user = get_user

    def __call__(self, f):
        def wrapper(*args, **kwargs):
            if not request.is_secure:
                url = request.url.replace('http://', 'https://', 1)
                return redirect(url, code=HTTPStatus.MOVED_PERMANENTLY)
            user = self._get_user()
            if not user:
                abort(HTTPStatus.FORBIDDEN, 'Not allowed')
            return f(user, *args, **kwargs)
        wrapper.__doc__ = f.__doc__
        wrapper.__name__ = f.__name__
        return wrapper


def error_msgs():
    return {
        'error': fields.String(enum=[errorMsg.value for errorMsg in RegistrationStatus])
    }
