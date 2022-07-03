from http import HTTPStatus
from flask import make_response, redirect, request, session
from flask_restx import Resource  # type: ignore
from werkzeug.security import check_password_hash

import secrets
from abc import ABC, abstractmethod

from flask_authbp import user
from flask_authbp._utility import initialize_blueprint, add_register_route


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

    @abstractmethod
    def remove_session(self, sessionId):
        ...


def create_blueprint(storage: Storage):
    '''
    Returns the blueprint and authorization decorator for session based authorization
    '''
    bp, ns = initialize_blueprint()
    add_login_route(ns, storage)
    add_register_route(ns, storage)
    add_logout_route(ns, storage)
    return bp, generate_permission_decorator(ns, storage)


def generate_session_id(storage: Storage):
    while True:
        sessionId = secrets.token_urlsafe()
        if not storage.find_session(sessionId):
            break
    return sessionId


def add_login_route(ns, storage: Storage):
    @ns.route('/login')
    class Login(Resource):
        @ns.expect(ns.model('UserLogin', user.name_and_pass()))
        @ns.response(HTTPStatus.OK, 'Success')
        @ns.response(HTTPStatus.UNAUTHORIZED, 'Incorrect username or password')
        @ns.response(HTTPStatus.MOVED_PERMANENTLY, 'Insecure connection')
        def post(self):
            if not request.is_secure:
                url = request.url.replace('http://', 'https://', 1)
                return redirect(url, code=HTTPStatus.MOVED_PERMANENTLY)
            username = ns.payload['username']
            passwordHash = storage.find_password_hash(username)
            if not passwordHash:
                ns.abort(HTTPStatus.UNAUTHORIZED, 'Incorrect username or password')

            if check_password_hash(passwordHash, ns.payload['password']):
                sessionId = generate_session_id(storage)
                storage.store_session(sessionId, username)
                session['_id'] = sessionId
                return 'Success'

            ns.abort(HTTPStatus.UNAUTHORIZED, 'Incorrect username or password')


def add_logout_route(ns, storage: Storage):
    @ns.route('/logout')
    class Logout(Resource):
        @ns.response(HTTPStatus.OK, 'Success')
        @ns.response(HTTPStatus.FORBIDDEN, 'Authorization missing')
        @ns.response(HTTPStatus.MOVED_PERMANENTLY, 'Insecure connection')
        def post(self):
            if not request.is_secure:
                url = request.url.replace('http://', 'https://', 1)
                return redirect(url, code=HTTPStatus.MOVED_PERMANENTLY)
            if '_id' in session:
                storage.remove_session(session['_id'])
                session.pop('_id')
                return HTTPStatus.OK
            else:
                ns.abort(HTTPStatus.FORBIDDEN, 'Authentication missing')



def generate_permission_decorator(ns, storage: Storage):
    def permission_required(f):
        def wrapper(*args, **kwargs):
            if not request.is_secure:
                url = request.url.replace('http://', 'https://', 1)
                return redirect(url, code=HTTPStatus.MOVED_PERMANENTLY)
            if '_id' in session:
                currentUser = storage.find_session(session['_id'])
                return f(*args, **kwargs, user=currentUser)
            else:
                ns.abort(HTTPStatus.FORBIDDEN, 'Authentication missing')
        wrapper.__doc__ = f.__doc__
        wrapper.__name__ = f.__name__
        return wrapper
    return permission_required
