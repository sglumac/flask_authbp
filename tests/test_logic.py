#!/usr/bin/env python

"""Tests for `flask_authbp` package."""


from ssl import cert_time_to_seconds
from parameterized import parameterized, parameterized_class

import unittest

from tests.utility import create_jwt_app


@parameterized_class(
    ('app',), [
        (create_jwt_app('testing_app'),)
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
        self.assertEqual(
            response.json['message'],
            'Password should have 6-64 symbols, required upper and lower case letters. Can contain !@#$%_'
        )

    def test_register_invalid_user(self):
        response = self._testClient.post('/register', json={
            'username': '_J',
            'password': 'Johny1234'
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json['message'],
            'Username should have 4-16 symbols, can contain A-Z, a-z, 0-9, _ ' +
            '(_ can not be at the begin/end and can not go in a row (__))'
        )

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
        self.assertEqual(response.json['message'],
                         'This username already exists')

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

    def test_accepted_authorization(self):
        testUser = {
            'username': 'TestTokenUser',
            'password': 'TestTokenUser1234!'
        }
        registerResponse = self._testClient.post('/register', json=testUser)
        self.assertEqual(registerResponse.status_code, 200)
        loginResponse = self._testClient.post('/login', json=testUser)
        self.assertEqual(loginResponse.status_code, 200)
        accessToken = loginResponse.json['access_token']
        testData = {'data': 'test'}
        authorization = {'Authorization': f'access_token {accessToken}'}
        testingResponse = self._testClient.post(
            '/testing/resource', json=testData, headers=authorization)
        self.assertEqual(testingResponse.status_code, 200)
