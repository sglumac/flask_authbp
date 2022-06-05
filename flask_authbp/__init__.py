"""Top-level package for Flask Auth Blueprint."""

__author__ = """Slaven Glumac"""
__email__ = 'slaven.glumac@gmail.com'
__version__ = '0.1.1'

from flask import request, current_app, Blueprint
from flask_restx import Resource, Namespace, fields, Api  # type: ignore
from werkzeug.security import check_password_hash, generate_password_hash

import re
import jwt
import datetime
import hashlib

from .model import Storage


# 4-16 symbols, can contain A-Z, a-z, 0-9, _
# # (_ can not be at the begin/end and can not go in a row (__))
USERNAME_REGEXP = r'^(?![_])(?!.*[_]{2})[a-zA-Z0-9._]+(?<![_])$'

# 6-64 symbols, required upper and lower case letters. Can contain !@#$%_  .
PASSWORD_REGEXP = r'^(?=.*[\d])(?=.*[A-Z])(?=.*[a-z])[\w\d!@#$%_]{6,64}$'


def create_blueprint(storage: Storage):
    '''
    Returns the blueprint and authorization decorator
    '''
    blueprint = Blueprint('auth', __name__, url_prefix='/')
    api = Api(blueprint)
    ns = Namespace('auth', 'Authentication and authorization', path='/')
    api.add_namespace(ns)

    UserApiModel = api.model('User', {
        'username': fields.String(required=True)
    })

    RegisterApiModel = api.model('Register', {
        'username': fields.String(required=True),
        'password': fields.String(required=True)
    })

    ReturnTokenApiModel = api.model('ReturnToken', {
        'access_token': fields.String(required=True),
        'refresh_token': fields.String(required=True)
    })

    @ns.route('/register')
    class Register(Resource):
        @ns.expect(RegisterApiModel, validate=True)
        @ns.marshal_with(UserApiModel)
        @ns.response(400, 'username or password incorrect')
        def post(self):
            username = ns.payload['username']
            if not re.search(USERNAME_REGEXP, username):
                ns.abort(
                    400,
                    'Username should have 4-16 symbols, can contain A-Z, a-z, 0-9, _ ' +
                    '(_ can not be at the begin/end and can not go in a row (__))'
                )

            if not re.search(PASSWORD_REGEXP, ns.payload['password']):
                ns.abort(
                    400, 'Password should have 6-64 symbols, required upper and lower case letters. Can contain !@#$%_')

            if storage.find_password_hash(username):
                ns.abort(400, 'This username already exists')

            passwordHash = generate_password_hash(ns.payload['password'])
            storage.store_user(username, passwordHash)

            return {'username': username}

    @ns.route('/login')
    class Login(Resource):
        @ns.expect(RegisterApiModel)
        @ns.response(200, 'Success', ReturnTokenApiModel)
        @ns.response(401, 'Incorrect username or password')
        def post(self):
            """
            Look implementation notes
            This API implemented JWT. Token's payload contain:
            'uid' (user id),
            'exp' (expiration date of the token),
            'iat' (the time the token is generated)
            """
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

    def authorization_required(f):
        def wrapper(*args, **kwargs):
            authHeader = request.headers.get('Authorization')
            currentUser = None
            if authHeader:
                try:
                    accessToken = authHeader.split(' ')[1]

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

    @ns.route('/refresh')
    class Refresh(Resource):
        @ns.expect(ns.model('RefreshToken', {'refresh_token': fields.String(required=True)}), validate=True)
        @ns.response(200, 'Success', ReturnTokenApiModel)
        def post(self):
            _refresh_token = ns.payload['refresh_token']

            try:
                payload = jwt.decode(
                    _refresh_token, current_app.config['SECRET_KEY'])

                refreshToken = RefreshToken.query.filter_by(
                    user_id=payload['uid'], refresh_token=_refresh_token).first()

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

    return blueprint, authorization_required
