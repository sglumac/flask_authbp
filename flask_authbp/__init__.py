"""Top-level package for Flask Auth Blueprint."""

__author__ = """Slaven Glumac"""
__email__ = 'slaven.glumac@gmail.com'
__version__ = '0.1.4'

from flask import Blueprint
from flask_restx import Namespace, Api  # type: ignore

from . import sessionbased


def create_blueprint(storage: sessionbased.Storage):
    '''
    Returns the blueprint and authorization decorator
    '''
    blueprint = Blueprint('auth', __name__, url_prefix='/')
    api = Api(blueprint)
    ns = Namespace('auth', 'Authentication and authorization', path='/')
    api.add_namespace(ns)

    sessionbased.add_register_route(ns, storage)
    sessionbased.add_login_route(ns, storage)

    return blueprint, sessionbased.generate_permission_decorator(ns, storage)
