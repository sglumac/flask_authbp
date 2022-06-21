from typing import Tuple
from flask import Blueprint
from flask_restx import Namespace, Api  # type: ignore


def initialize_blueprint() -> Tuple[Blueprint, Namespace]:
    '''
    Returns the blueprint and authorization decorator
    '''
    bp = Blueprint('auth', __name__, url_prefix='/')
    api = Api(bp)
    ns = Namespace('auth', 'Authentication and authorization', path='/')
    api.add_namespace(ns)

    return bp, ns
