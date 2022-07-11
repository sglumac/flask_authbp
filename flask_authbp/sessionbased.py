from http import HTTPStatus
from flask import abort, redirect, request, session  # type: ignore

import secrets
from abc import ABC, abstractmethod

from flask_restx import Resource

from ._utility import authentication_blueprint, PermissionDecorator
from .types import Authentication


class Storage(ABC):
    @abstractmethod
    def store_user(self, username: str, passwordHash: str) -> None:
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
    bp, ns = authentication_blueprint(
        Authentication(storage.find_password_hash, storage.store_user, _SessionGenerator(storage))
    )
    add_logout_route(ns, storage)
    return bp, PermissionDecorator(_UserGetter(storage))


class _SessionGenerator:
    def __init__(self, storage) -> None:
        self._storage = storage

    def _generate_session_id(self):
        while True:
            sessionId = secrets.token_urlsafe()
            if not self._storage.find_session(sessionId):
                break
        return sessionId

    def __call__(self, username):
        sessionId = self._generate_session_id()
        session['_id'] = sessionId
        self._storage.store_session(sessionId, username)


class _UserGetter:
    def __init__(self, storage) -> None:
        self._storage = storage

    def __call__(self):
        if '_id' not in session:
            abort(HTTPStatus.FORBIDDEN, 'Login missing')
        return self._storage.find_session(session['_id'])


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
