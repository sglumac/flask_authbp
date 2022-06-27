from flask import request, current_app
from flask_restx import Resource, fields  # type: ignore
from werkzeug.security import check_password_hash, generate_password_hash

import jwt
import datetime
import hashlib
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


def create_blueprint(storage: Storage):
    '''
    Returns the blueprint and authorization decorator for token based authentication
    '''
    bp, ns = initialize_blueprint()
    add_login_route(ns, storage)
    add_register_route(ns, storage)
    return bp, generate_permission_decorator(ns, storage)


def create_blueprint(storage: Storage):
    bp, ns = initialize_blueprint()
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

                userAgentString = request.user_agent.string.encode('utf-8')
                userAgentHash = hashlib.md5(userAgentString).hexdigest()

                refreshToken = storage.find_refresh_token(userAgentHash)

                if not refreshToken:
                    refreshToken = storage.store_refresh_token(username, refreshTokenEncoded, userAgentHash)
                else:
                    refreshToken.refresh_token = refreshTokenEncoded

                return {'access_token': accessTokenEncoded, 'refresh_token': refreshTokenEncoded}, 200

            ns.abort(401, 'Incorrect username or password')


def generate_permission_decorator(ns, storage: Storage):
    def authorization_required(f):
        def wrapper(*args, **kwargs):
            authHeader = request.headers.get('Authorization')
            currentUser = None
            if authHeader:
                try:
                    accessToken = authHeader.split(' ')[1]

                    try:
                        token = jwt.decode(accessToken, current_app.config['SECRET_KEY'], algorithms=['HS256'])
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

    @ns.route('/refresh')
    class Refresh(Resource):
        @ns.expect(ns.model('RefreshToken', {'refresh_token': fields.String(required=True)}), validate=True)
        # @ns.response(200, 'Success', ReturnTokenApiModel)
        def post(self):
            _refresh_token = ns.payload['refresh_token']

            try:
                payload = jwt.decode(
                    _refresh_token, current_app.config['SECRET_KEY'])

                refreshToken = dict()#RefreshToken.query.filter_by(user_id=payload['uid'], refresh_token=_refresh_token).first()

                if not refreshToken:
                    raise jwt.InvalidIssuerError

                # Generate new pair
                _access_token = jwt.encode({'uid': refreshToken.user_id,
                                            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
                                            'iat': datetime.datetime.utcnow()},
                                           current_app.config['SECRET_KEY']).decode('utf-8')
                _refresh_token = jwt.encode({'uid': refreshToken.user_id,
                                             'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30),
                                             'iat': datetime.datetime.utcnow()},
                                            current_app.config['SECRET_KEY']).decode('utf-8')

                refreshToken.refresh_token = _refresh_token
                storage.store_refresh_token(refreshToken)

                return {'access_token': _access_token, 'refresh_token': _refresh_token}, 200

            except jwt.ExpiredSignatureError as e:
                raise e
            except (jwt.DecodeError, jwt.InvalidTokenError) as e:
                raise e
            except Exception:
                ns.abort(401, 'Unknown token error')

    return authorization_required
