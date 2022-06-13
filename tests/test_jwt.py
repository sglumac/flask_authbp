#!/usr/bin/env python

"""Tests for `flask_authbp` package."""


from flask import Config, Flask
import unittest
import time

from tests.utility import create_jwt_app


class TestJwt(unittest.TestCase):
    def test_expired_access_token(self):
        shortAccessExpSecs = 1
        app = create_jwt_app('short_access', accessExpSecs=shortAccessExpSecs)
        self._testClient = app.test_client()
        testClient = app.test_client()
        testUser = {
            'username': 'ExpiredAccessExpUser',
            'password': 'ExpiredAccessExpUser1234!'
        }
        registerResponse = testClient.post('/register', json=testUser)
        self.assertEqual(registerResponse.status_code, 200)
        loginResponse = testClient.post('/login', json=testUser)
        self.assertEqual(loginResponse.status_code, 200)
        accessToken = loginResponse.json['access_token']
        time.sleep(shortAccessExpSecs + 1)
        testData = {'data': 'test'}
        authorization = {'Authorization': f'access_token {accessToken}'}
        testingResponse = testClient.post(
            '/testing/resource', json=testData, headers=authorization)
        self.assertEqual(testingResponse.status_code, 401)
