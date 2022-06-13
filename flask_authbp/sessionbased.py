from typing import Set
from flask import make_response, request, current_app
from flask_restx import Resource
from requests import session
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

from datetime import datetime
from abc import ABC, abstractmethod

from .model import Storage
from . import user


def generate_session_cookie(userId):
    return jwt.encode({
        datetime.utcnow()
    })


class Storage(ABC):
    @abstractmethod
    def store_user(self, username: str, passwordHash: str) -> bool:
        ...

    @abstractmethod
    def find_password_hash(self, username):
        ...

    @abstractmethod
    def store_session(self, sessionId, sessionData):
        ...


def add_register(ns, storage: Storage):

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
                ns.abort(400, user.already_exists_msg())

            passwordHash = generate_password_hash(password)
            storage.store_user(username, passwordHash)

            return {'username': username}


def add_login(ns, storage: Storage):
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
                userAgent = request.headers.get('User-Agent')
                response = make_response()
                sessionId = None
                sessionDataEncoded = jwt.encode({

                })
                storage.store_session(sessionId, sessionDataEncoded)
                response.set_cookie('sessionId', sessionId)
                return response

            ns.abort(401, 'Incorrect username or password')


def generate_permission_decorator(ns, storage: Storage):
    def permission_required(f):
        def wrapper(*args, **kwargs):
            if 'sessionId' in request.cookies:
                sessionId = request.cookies.get('sessionId')
                userAgent = request.headers.get('User-Agent')
                sessionDataEncoded = storage.get_session(sessionId)
                sessionData = jwt.decode(sessionDataEncoded)
            else:
                ns.abort(401, 'Authentication missing')
                currentUser = None
                try:

                    try:
                        import time
                        current = time.time()
                        token = jwt.decode(
                            accessToken, current_app.config['SECRET_KEY'], algorithms=['HS256'])
                        currentUser = token['uid']
                    except jwt.ExpiredSignatureError as e:
                        ns.abort(401, e)
                    except (jwt.DecodeError, jwt.InvalidTokenError) as e:
                        raise e
                    except Exception:
                        ns.abort(401, 'Unknown token error')

                except IndexError:
                    raise jwt.InvalidTokenError
            else:
                ns.abort(403, 'Token required')
            return f(*args, **kwargs, user=currentUser)

        wrapper.__doc__ = f.__doc__
        wrapper.__name__ = f.__name__
        return wrapper
    return permission_required
