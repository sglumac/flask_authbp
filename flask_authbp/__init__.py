"""Top-level package for Flask Auth Blueprint."""

__author__ = """Slaven Glumac"""
__email__ = 'slaven.glumac@gmail.com'
__version__ = '0.1.4'


from http import HTTPStatus
from typing import Callable

from flask import abort

from . import sessionbased, tokenbased
