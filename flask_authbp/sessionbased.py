from typing import NamedTuple, Optional
from flask import session  # type: ignore
from flask_authbp.auth import PermissionChecker
from flask_restx import Resource  # type: ignore
from werkzeug.security import check_password_hash  # type: ignore

import secrets
from abc import ABC, abstractmethod

from flask_authbp import user
from flask_authbp._utility import auth_to_blueprint, add_register_route


class Storage(ABC):
    @abstractmethod
    def store_user(self, username: str, passwordHash: str) -> bool:
        ...

    @abstractmethod
    def find_password_hash(self, username):
        ...

    @abstractmethod
    def store_session(self, sessionId, username):
        ...

    @abstractmethod
    def find_session(self, sessionId):
        ...


def auth_to_blueprint(storage: Storage):
    '''
    Returns the blueprint and authorization decorator for session based authorization
    '''
    bp, ns = auth_to_blueprint()
    add_login_route(ns, storage)
    add_register_route(ns, storage)
    return bp, generate_permission_decorator(ns, storage)


def add_login_route(ns, storage: Storage):
    @ns.route('/login')
    class Login(Resource):
        @ns.expect(ns.model('UserLogin', user.name_and_pass()))
        @ns.response(200, 'Success')
        @ns.response(401, 'Incorrect username or password')
        def post(self):
            username = ns.payload['username']
            passwordHash = storage.find_password_hash(username)
            if not passwordHash:
                ns.abort(401, 'Incorrect username or password')

            if check_password_hash(passwordHash, ns.payload['password']):
                sessionId = generate_session_id(storage)
                storage.store_session(sessionId, username)
                session['_id'] = sessionId
                return 'Success'

            ns.abort(401, 'Incorrect username or password')


def generate_permission_decorator(ns, storage: Storage):
    def permission_required(f):
        def wrapper(*args, **kwargs):
            if '_id' in session:
                currentUser = storage.find_session(session['_id'])
                return f(*args, **kwargs, user=currentUser)
            else:
                ns.abort(403, 'Authentication missing')
        wrapper.__doc__ = f.__doc__
        wrapper.__name__ = f.__name__
        return wrapper
    return permission_required

from auth import AuthImplementation, LoginReport, LoginStatus, Password, Username


class Session(NamedTuple):
    id: int


class Login():
    def __init__(self, storage: Storage):
        self._storage = storage

    def generate_session_id(self):
        while True:
            sessionId = secrets.token_urlsafe()
            if not self._storage.find_session(sessionId):
                break
        return sessionId

    def __call__(self, username: Username, password: Password) -> LoginReport[Session]:
        passwordHash = self._storage.find_password_hash(username)
        if not passwordHash:
            return LoginReport(LoginStatus.NonExistingUsername, None)

        if check_password_hash(passwordHash, password):
            sessionId = self._generate_session_id()
            self._storage.store_session(sessionId, username)
            return LoginReport(LoginStatus.Success, Session(sessionId))
        else:
            return LoginReport(LoginStatus.WrongPassword, None)


class PermissionChecker():
    pass

def auth_implementation() -> AuthImplementation:
    return AuthImplementation()
