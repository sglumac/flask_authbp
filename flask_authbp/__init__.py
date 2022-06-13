"""Top-level package for Flask Auth Blueprint."""

__author__ = """Slaven Glumac"""
__email__ = 'slaven.glumac@gmail.com'
__version__ = '0.1.4'

from flask import request, Blueprint
from flask_restx import, Namespace, fields, Api  # type: ignore

from .model import Storage


def create_blueprint(storage: Storage):
    '''
    Returns the blueprint and authorization decorator
    '''
    blueprint = Blueprint('auth', __name__, url_prefix='/')
    api = Api(blueprint)
    ns = Namespace('auth', 'Authentication and authorization', path='/')
    api.add_namespace(ns)

    return blueprint, permission_required
