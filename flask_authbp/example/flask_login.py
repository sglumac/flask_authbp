from http import HTTPStatus
from typing import Type
from flask import Config, Flask
from flask_login import UserMixin
from flask_restx import Api, Resource
from flask_authbp.flask_login import Storage, add_authbp
from flask_sqlalchemy import SQLAlchemy, orm


class TestingConfig(Config):
        DATABASE_URI = 'sqlite:///:memory:'
        TESTING = True
        SECRET_KEY = 'my secret'
        PREFERRED_URL_SCHEME = 'https'


app = Flask('Flask Auth Bluperint Example - Flask-Login')
app.config.from_object(TestingConfig)
db = SQLAlchemy()
db.init_app(app)

class ExampleUser(UserMixin, db.Model):
    username = db.Column(db.String(100), unique=True, primary_key=True)
    passwordHash = db.Column(db.String(100))

    def __init__(self, username, passwordHash):
        self.username = username
        self.passwordHash = passwordHash

    def get_id(self):
        return self.username


class FlaskLoginTestStorage(Storage):
    def find_password_hash(self, username):
        user = ExampleUser.query.get(username)
        if user:
            return user.passwordHash
        else:
            return None

    def store_user(self, username, passwordHash):
        if self.find_password_hash(username):
            return False
        else:
            db.session.add(ExampleUser(username, passwordHash))
            db.session.commit()
            return True

    def load_user(self, username) -> Type[UserMixin]:
        return ExampleUser.query.get(username)


api = Api(app)
permission_required = add_authbp(app, FlaskLoginTestStorage())
with app.app_context():
    db.create_all()

@api.route('/testing/resource')
class TestingResource(Resource):
    @permission_required
    def post(self, user):
        return HTTPStatus.OK

    def get(self):
        return HTTPStatus.OK

