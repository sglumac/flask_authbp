from http import HTTPStatus
from typing import Callable, Tuple, Type
from flask import Blueprint, Flask, abort, redirect, request, session
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user  # type: ignore
from flask_restx import Resource  # type: ignore

from abc import ABC, abstractmethod

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
    def load_user(self, username) -> Type[UserMixin]:
        ...


def add_authbp(app: Flask, storage: Storage) -> Callable:
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)
    login_manager.user_loader(storage.load_user)
    bp, ns = authentication_blueprint(
        Authentication(storage.find_password_hash, storage.store_user, _SessionGenerator(storage))
    )
    add_logout_route(ns)
    app.register_blueprint(bp)
    return PermissionDecorator(lambda: None if current_user.is_anonymous else current_user)


class _SessionGenerator:
    def __init__(self, storage) -> None:
        self._storage = storage

    def __call__(self, username):
        login_user(self._storage.load_user(username))


def add_logout_route(ns):
    @ns.route('/logout')
    class Logout(Resource):
        @ns.response(HTTPStatus.OK, 'Success')
        @ns.response(HTTPStatus.FORBIDDEN, 'Authorization missing')
        @ns.response(HTTPStatus.MOVED_PERMANENTLY, 'Insecure connection')
        @login_required
        def post(self):
            logout_user()
            return HTTPStatus.OK
