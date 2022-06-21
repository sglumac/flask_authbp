#!/usr/bin/env python

"""Tests for `flask_authbp` package."""


from parameterized import parameterized_class

import unittest
from flask_authbp import user

from tests.utility import create_sb_app


@parameterized_class(
    ('app',), [
        (create_sb_app('sb_auth_testing_app'),)
    ]
)
class TestAuth(unittest.TestCase):
    def setUp(self):
        self._testClient = self.app.test_client()

    def test_register_invalid_pass(self):
        response = self._testClient.post('/register', json={
            'username': 'Johnny',
            'password': 'johnny'
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json['message'], user.ErrorMsg.InvalidPassword.value)

    def test_register_invalid_user(self):
        response = self._testClient.post('/register', json={
            'username': '_J',
            'password': 'Johny1234'
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json['message'], user.ErrorMsg.InvalidUsername.value)

    def test_register_success(self):
        response = self._testClient.post('/register', json={
            'username': 'Johny',
            'password': 'Johny1234!'
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['username'], 'Johny')

    def test_register_same_user(self):
        userData = {
            'username': 'DoubleUser',
            'password': 'DoubleUser1234!'
        }
        response = self._testClient.post('/register', json=userData)
        self.assertEqual(response.status_code, 200)

        response = self._testClient.post('/register', json=userData)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json['message'], user.ErrorMsg.UserExists.value)

    def test_non_existing_user_login(self):
        response = self._testClient.post('/login', json={
            'username': 'NonExistingLogin',
            'password': 'Login1234!'
        })
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json['message'],
                         'Incorrect username or password')

    def test_wrong_pass_login(self):
        response = self._testClient.post('/register', json={
            'username': 'WrongPassUser',
            'password': 'Johny1234!'
        })
        self.assertEqual(response.status_code, 200)
        response = self._testClient.post('/login', json={
            'username': 'WrongPassUser',
            'password': 'WrongPass1234!'
        })
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json['message'],
                         'Incorrect username or password')

    def test_login_success(self):
        testUser = {
            'username': 'CorrectPassUser',
            'password': 'CorrectPassUser1234!'
        }
        response = self._testClient.post('/register', json=testUser)
        self.assertEqual(response.status_code, 200)
        response = self._testClient.post('/login', json=testUser)
        self.assertEqual(response.status_code, 200)

    def test_rejected_authorization(self):
        response = self._testClient.post('/testing/resource')
        self.assertEqual(response.status_code, 403)
