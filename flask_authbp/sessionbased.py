from flask import current_app
from flask_restx import Resource
from werkzeug.security import generate_password_hash, check_password_hash

import datetime

from .model import Storage
from . import user


def add_register(ns, storage: Storage):

    @ns.route('/register')
    class Register(Resource):
        @ns.expect(ns.model('UserLogin', user.name_and_pass()), validate=True)
        @ns.marshal_with(ns.model('Username', user.only_name()))
        @ns.response(400, 'username or password incorrect')
        def post(self):
            username = ns.payload['username']
            password = ns.payload['password']
            if not user.name_valid(username):
                ns.abort(400,
                    'Username should have 4-16 symbols, can contain A-Z, a-z, 0-9, _ ' +
                    '(_ can not be at the begin/end and can not go in a row (__))'
                )

            if not user.pass_valid(password):
                ns.abort(
                    400, 'Password should have 6-64 symbols, required upper and lower case letters. Can contain !@#$%_')

            if storage.find_password_hash(username):
                ns.abort(400, 'This username already exists')

            passwordHash = generate_password_hash(password)
            storage.store_user(username, passwordHash)

            return {'username': username}


def add_login(ns, storage: Storage):
    @ns.route('/login')
    class Login(Resource):
        @ns.expect(ns.model('UserLogin', user.name_and_pass()))
        @ns.response(200, 'Success', ns.model)
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
    pass
