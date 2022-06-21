from flask_restx import fields

import re
from enum import Enum


class ErrorMsg(Enum):
    InvalidUsername = 'Invalid username'
    InvalidPassword = 'Invalid password'
    UserExists = 'Username already exists'


def error_msgs():
    return {
        'error': fields.String(enum=[errorMsg.value for errorMsg in ErrorMsg])
    }


def name_valid(username):
    '''
    4-16 symbols, can contain A-Z, a-z, 0-9, _ (_ can not be at the begin/end and can not go in a row (__))
    '''
    return re.search(
        r'^(?![_])(?!.*[_]{2})[a-zA-Z0-9._]+(?<![_])$',
        username
    )


def pass_valid(password):
    '''
    6-64 symbols, required upper and lower case letters. Can contain !@#$%_  .
    '''
    return re.search(
        r'^(?=.*[\d])(?=.*[A-Z])(?=.*[a-z])[\w\d!@#$%_]{6,64}$',
        password
    )


def only_name():
    return {
        'username': fields.String(required=True)
    }


def name_and_pass():
    return {
        'username': fields.String(required=True),
        'password': fields.String(required=True)
    }
