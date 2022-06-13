from flask import Config, Flask
from flask_restx import Api, Resource

import flask_authbp


class TestStorage(flask_authbp.Storage):
    def __init__(self):
        self._passwordHashes = dict()
        self._refreshTokens = dict()

    def find_password_hash(self, username):
        return self._passwordHashes[username] if username in self._passwordHashes else None

    def store_refresh_token(self, username, refreshToken, userAgentHash):
        self._refreshTokens[userAgentHash] = refreshToken

    def store_user(self, username, password):
        self._passwordHashes[username] = password

    def find_refresh_token(self, userAgentHash):
        return self._refreshTokens[userAgentHash] if userAgentHash in self._refreshTokens else None

    def update_refresh_token(self, userAgentHash, refreshToken):
        self._refreshTokens[userAgentHash] = refreshToken


def create_jwt_app(title, accessExpSecs=15 * 60):
    class TestingConfig(Config):
        DATABASE_URI = 'sqlite:///:memory:'
        TESTING = True
        SECRET_KEY = 'my secret'
        ACCESS_EXP_SECS = accessExpSecs
        REFRESH_EXP_SECS = 30 * 24 * 60 * 60

    storage = TestStorage()
    blueprint, authorization_required = flask_authbp.create_blueprint(storage)
    app = Flask(title)
    app.config.from_object(TestingConfig)
    app.register_blueprint(blueprint)
    api = Api(app)

    @api.route('/testing/resource')
    class TestingResource(Resource):
        @authorization_required
        def post(self, user):
            return 200

        def get(self):
            return 'Mislav'

    return app
