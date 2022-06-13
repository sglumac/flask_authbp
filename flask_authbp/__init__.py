"""Top-level package for Flask Auth Blueprint."""

__author__ = """Slaven Glumac"""
__email__ = 'slaven.glumac@gmail.com'
__version__ = '0.1.4'

import enum
from flask import request, current_app, Blueprint
from flask_restx import Resource, Namespace, fields, Api  # type: ignore
from werkzeug.security import check_password_hash, generate_password_hash

import jwt
import datetime
import hashlib

from .model import Storage
from . import user


def return_token_fields():
    return {
        'access_token': fields.String(required=True),
        'refresh_token': fields.String(required=True)
    }


def create_blueprint(storage: Storage):
    '''
    Returns the blueprint and authorization decorator
    '''
    blueprint = Blueprint('auth', __name__, url_prefix='/')
    api = Api(blueprint)
    ns = Namespace('auth', 'Authentication and authorization', path='/')
    api.add_namespace(ns)

    UsernameApiModel = ns.model('Username', user.only_name())
    UserLoginApiModel = ns.model('UserLogin', user.name_and_pass())

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
