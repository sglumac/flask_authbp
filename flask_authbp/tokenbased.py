from http import HTTPStatus
from typing import Callable, Tuple
from flask import Blueprint, abort, request, current_app
from flask_restx import Resource, fields  # type: ignore
from werkzeug.security import check_password_hash

import jwt
import datetime
from abc import ABC, abstractmethod

from flask_authbp import user
from flask_authbp._utility import authentication_blueprint, PermissionDecorator
from flask_authbp.types import Authentication


class Storage(ABC):
    @abstractmethod
    def store_user(self, username: str, passwordHash: str) -> None:
        ...

    @abstractmethod
    def find_password_hash(self, username):
        ...

    @abstractmethod
    def find_refresh_token(self, userAgentHash):
        ...

    @abstractmethod
    def store_refresh_token(self, username, refreshTokenEncoded, userAgentHash):
        ...


def return_token_fields():
    return {
        'access_token': fields.String(required=True),
        'refresh_token': fields.String(required=True)
    }


def create_blueprint(storage: Storage) -> Tuple[Blueprint, Callable]:
    '''
    Returns the blueprint and authorization decorator for token based authentication
    '''
    bp, _ = authentication_blueprint(
        Authentication(storage.find_password_hash, storage.store_user, _TokenGenerator())
    )
    return bp, PermissionDecorator(_UserGetter(storage))


class _TokenGenerator:
    def __init__(self) -> None:
        pass

    def __call__(self, username):
        accessPayload = {
            'uid': username,
            'exp': datetime.datetime.utcnow() +
            datetime.timedelta(seconds=current_app.config['ACCESS_EXP_SECS']),
            'iat': datetime.datetime.utcnow()
        }
        accessTokenEncoded = jwt.encode(
            accessPayload,
            current_app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        refreshPayload = {
            'uid': username,
            'exp': datetime.datetime.utcnow()
            + datetime.timedelta(seconds=current_app.config['REFRESH_EXP_SECS']),
            'iat': datetime.datetime.utcnow()
        }
        refreshTokenEncoded = jwt.encode(
            refreshPayload,
            current_app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        return {'access_token': accessTokenEncoded, 'refresh_token': refreshTokenEncoded}


class _UserGetter:
    def __init__(self, storage) -> None:
        self._storage = storage

    def __call__(self):
        authHeader = request.headers.get('Authorization')
        if authHeader:
            try:
                accessToken = authHeader.split(' ')[1]
                try:
                    token = jwt.decode(accessToken, current_app.config['SECRET_KEY'], algorithms=['HS256'])
                    return token['uid']
                except jwt.ExpiredSignatureError as e:
                    abort(HTTPStatus.FORBIDDEN, e)
                except (jwt.DecodeError, jwt.InvalidTokenError) as e:
                    raise e
                except Exception:
                    abort(HTTPStatus.FORBIDDEN, 'Unknown token error')
            except IndexError:
                raise jwt.InvalidTokenError
        else:
            abort(HTTPStatus.FORBIDDEN, 'Token required')
