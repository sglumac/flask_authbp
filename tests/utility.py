from http import HTTPStatus
from flask import Config, Flask  # type: ignore
from flask_restx import Api, Resource  # type: ignore

import flask_authbp


class SbTestStorage(flask_authbp.sessionbased.Storage):
    def __init__(self):
        self._passwordHashes = dict()
        self._session = dict()

    def find_password_hash(self, username):
        return self._passwordHashes[username] if username in self._passwordHashes else None

    def store_user(self, username, passwordHash):
        if passwordHash in self._passwordHashes:
            return False
        else:
            self._passwordHashes[username] = passwordHash
            return True

    def find_session(self, sessionId):
        return self._session[sessionId] if sessionId in self._session else None

    def store_session(self, sessionId, username):
        self._session[sessionId] = username

    def remove_session(self, sessionId):
        self._session.pop(sessionId)


def create_sb_app(title, urlScheme='https', accessExpSecs=15 * 60):
    class TestingConfig(Config):
        DATABASE_URI = 'sqlite:///:memory:'
        TESTING = True
        SECRET_KEY = 'my secret'
        ACCESS_EXP_SECS = accessExpSecs
        REFRESH_EXP_SECS = 30 * 24 * 60 * 60
        PREFERRED_URL_SCHEME = urlScheme

    storage = SbTestStorage()
    blueprint, permission_required = flask_authbp.sessionbased.create_blueprint(storage)
    app = Flask(title)
    app.config.from_object(TestingConfig)
    app.register_blueprint(blueprint)
    api = Api(app)

    @api.route('/testing/resource')
    class TestingResource(Resource):
        @permission_required
        def post(self, user):
            return HTTPStatus.OK

        def get(self):
            return 'Test'

    return app


class TokenTestStorage(flask_authbp.tokenbased.Storage):
    def __init__(self):
        self._passwordHashes = dict()
        self._refreshTokens = dict()

    def find_password_hash(self, username):
        return self._passwordHashes[username] if username in self._passwordHashes else None

    def store_user(self, username, passwordHash):
        if passwordHash in self._passwordHashes:
            return False
        else:
            self._passwordHashes[username] = passwordHash
            return True

    def find_refresh_token(self, userAgentHash):
        return self._refreshTokens[userAgentHash] if userAgentHash in self._refreshTokens else None

    def store_refresh_token(self, username, refreshTokenEncoded, userAgentHash):
        self._refreshTokens[userAgentHash] = (username, refreshTokenEncoded)


def create_jwt_app(title, accessExpSecs=15 * 60):
    class TestingConfig(Config):
        DATABASE_URI = 'sqlite:///:memory:'
        TESTING = True
        SECRET_KEY = 'my secret'
        ACCESS_EXP_SECS = accessExpSecs
        REFRESH_EXP_SECS = 30 * 24 * 60 * 60

    storage = TokenTestStorage()
    blueprint, permission_required = flask_authbp.tokenbased.create_blueprint(storage)
    app = Flask(title)
    app.config.from_object(TestingConfig)
    app.register_blueprint(blueprint)
    api = Api(app)

    @api.route('/testing/resource')
    class TestingResource(Resource):
        @permission_required
        def post(self, user):
            return HTTPStatus.OK

        def get(self):
            return HTTPStatus.OK

    return app
