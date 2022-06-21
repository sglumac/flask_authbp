from typing import Set
from flask import make_response, request, current_app
from flask_restx import Resource
from requests import session
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

import secrets
from datetime import datetime
from abc import ABC, abstractmethod
from itertools import count

from . import user


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


def generate_session_id(storage: Storage):
    while True:
        sessionId = secrets.token_urlsafe()
        if not storage.find_session(sessionId):
            break
    return sessionId


def add_register_route(ns, storage: Storage):
    @ns.route('/register')
    class Register(Resource):
        @ns.expect(ns.model('UserLogin', user.name_and_pass()), validate=True)
        @ns.marshal_with(ns.model('Username', user.only_name()))
        @ns.response(200, 'Success')
        @ns.response(400, ns.model('RegistrationError', user.error_msgs()))
        def post(self):
            username = ns.payload['username']
            password = ns.payload['password']
            if not user.name_valid(username):
                ns.abort(400, user.ErrorMsg.InvalidUsername.value)

            if not user.pass_valid(password):
                ns.abort(400, user.ErrorMsg.InvalidPassword.value)

            if storage.find_password_hash(username):
                ns.abort(400, user.ErrorMsg.UserExists.value)

            passwordHash = generate_password_hash(password)
            storage.store_user(username, passwordHash)

            return {'username': username}


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
                response = make_response()
                sessionId = generate_session_id(storage)
                storage.store_session(sessionId, username)
                response.set_cookie('sessionId', sessionId)
                return response

            ns.abort(401, 'Incorrect username or password')


def generate_permission_decorator(ns, storage: Storage):
    def permission_required(f):
        def wrapper(*args, **kwargs):
            if 'sessionId' in request.cookies:
                sessionId = request.cookies.get('sessionId')
                currentUser = storage.find_session(sessionId)
                return f(*args, **kwargs, user=currentUser)
            else:
                ns.abort(403, 'Authentication missing')
        wrapper.__doc__ = f.__doc__
        wrapper.__name__ = f.__name__
        return wrapper
    return permission_required
