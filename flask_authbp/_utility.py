import enum
from typing import Tuple
from flask import Blueprint
from flask_restx import Namespace, Api, Resource
from werkzeug.security import check_password_hash, generate_password_hash

from flask_authbp import user


def initialize_blueprint() -> Tuple[Blueprint, Namespace]:
    '''
    Returns the blueprint and authorization decorator
    '''
    bp = Blueprint('auth', __name__, url_prefix='/')
    api = Api(bp)
    ns = Namespace('auth', 'Authentication and authorization', path='/')
    api.add_namespace(ns)

    return bp, ns


def add_register_route(ns, storage):
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
