#!/usr/bin/env python

"""Tests for `flask_authbp` package."""


from flask import Config, Flask

import unittest
import time

import flask_authbp


def create_testing_app():
    class TestingConfig(Config):
        DATABASE_URI = 'sqlite:///:memory:'
        TESTING = True
        SECRET_KEY = 'my secret'
        ACCESS_EXP_SECS = 15 * 60
        REFRESH_EXP_SECS = 30 * 24 * 60 * 60

    app = Flask('testing_app')
    app.config.from_object(TestingConfig)
    app.register_blueprint(flask_authbp.blueprint)
    return app


def create_short_access_testing_app():
    class ShortAccessExpTestConfig(Config):
        DATABASE_URI = 'sqlite:///:memory:'
        TESTING = True
        SECRET_KEY = 'my secret'
        ACCESS_EXP_SECS = 1
        REFRESH_EXP_SECS = 30 * 24 * 60 * 60
    app = Flask('short_access_testing_app')
    app.config.from_object(ShortAccessExpTestConfig)
    app.register_blueprint(flask_authbp.blueprint)
    return app


class TestAuth(unittest.TestCase):
    def setUp(self):
        app = create_testing_app()
        self._testClient = app.test_client()

    def test_register_invalid_pass(self):
        response = self._testClient.post('/register', json={
            'username': 'Johnny',
            'password': 'johnny'
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json['message'], 'Password should have 6-64 symbols, required upper and lower case letters. Can contain !@#$%_')

    def test_register_invalid_user(self):
        response = self._testClient.post('/register', json={
            'username': '_J',
            'password': 'Johny1234'
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json['message'], 'Username should have 4-16 symbols, can contain A-Z, a-z, 0-9, _ (_ can not be at the begin/end and can not go in a row (__))')

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
        response = self._testClient.post('/register', json={
            'username': 'CorrectPassUser',
            'password': 'CorrectPassUser1234!'
        })
        self.assertEqual(response.status_code, 200)
        response = self._testClient.post('/login', json={
            'username': 'CorrectPassUser',
            'password': 'CorrectPassUser1234!'
        })
        self.assertEqual(response.status_code, 200)

    def test_rejected_authorization(self):
        response = self._testClient.post('/bookAd')
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
        bookAd = {
            'title': 'Steppenwolf',
            'imageFile': 'book.jpg'
        }
        authorization = {'Authorization': f'access_token {accessToken}'}
        bookAdResponse = self._testClient.post(
            '/bookAd', json=bookAd, headers=authorization)
        self.assertEqual(bookAdResponse.status_code, 200)

    def test_expired_access_token(self):
        app = create_short_access_testing_app()
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
        time.sleep(2)  # 1 second
        bookAd = {
            'title': 'Steppenwolf',
            'imageFile': 'book.jpg'
        }
        authorization = {'Authorization': f'access_token {accessToken}'}
        bookAdResponse = testClient.post(
            '/bookAd', json=bookAd, headers=authorization)
        self.assertEqual(bookAdResponse.status_code, 401)
        refreshResponse = None
        self.assertTrue(refreshResponse)
