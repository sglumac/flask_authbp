from http import HTTPStatus
from flask import Blueprint, abort, redirect, request  # type: ignore
from flask_restx import Namespace, Api, Resource, fields  # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash  # type: ignore

from typing import Tuple
import re

from flask_authbp.messages import LoginStatus, RegistrationStatus
from flask_authbp.types import Authentication


def name_valid(username):
    '''
    4-16 symbols, can contain A-Z, a-z, 0-9, _ (_ can not be at the begin/end and can not go in a row (__))
    '''
    return re.search(
        r'^(?![_])(?!.*[_]{2})[a-zA-Z0-9._]+(?<![_])$',
        username
    )


def pass_valid(password):
    '''
    6-64 symbols, required upper and lower case letters. Can contain !@#$%_  .
    '''
    return re.search(
        r'^(?=.*[\d])(?=.*[A-Z])(?=.*[a-z])[\w\d!@#$%_]{6,64}$',
        password
    )


def only_name():
    return {
        'username': fields.String(required=True)
    }


def name_and_pass():
    return {
        'username': fields.String(required=True),
        'password': fields.String(required=True)
    }


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
        @ns.expect(ns.model('UserLogin', name_and_pass()), validate=True)
        @ns.response(HTTPStatus.OK, 'Success')
        def post(self):
            username = ns.payload['username']
            password = ns.payload['password']
            if not name_valid(username):
                ns.abort(HTTPStatus.BAD_REQUEST, RegistrationStatus.InvalidUsername)

            if not pass_valid(password):
                ns.abort(HTTPStatus.BAD_REQUEST, RegistrationStatus.InvalidPassword)

            if user_exists(username):
                ns.abort(HTTPStatus.BAD_REQUEST, RegistrationStatus.UserExists)

            store_user(username, generate_password_hash(password))


def add_login_route(ns, find_password_hash, generate_session_info):
    @ns.route('/login')
    class Login(Resource):
        @ns.expect(ns.model('UserLogin', name_and_pass()))
        @ns.response(200, 'Success')
        @ns.response(401, LoginStatus.NonExistingUsername)
        def post(self):
            username = ns.payload['username']
            passwordHash = find_password_hash(username)

            if not passwordHash:
                ns.abort(HTTPStatus.UNAUTHORIZED, LoginStatus.NonExistingUsername)

            if check_password_hash(passwordHash, ns.payload['password']):
                response = generate_session_info(username)
                if response:
                    return response
                else:
                    return HTTPStatus.OK
            else:
                ns.abort(HTTPStatus.UNAUTHORIZED, LoginStatus.WrongPassword)


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
