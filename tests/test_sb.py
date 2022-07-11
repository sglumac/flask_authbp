import unittest

from tests.utility import create_sb_app


class TestSessionBased(unittest.TestCase):
    def setUp(self):
        self.app = create_sb_app('sb_specific_testing_app')

    def test_authorization_and_logout(self):
        testClient = self.app.test_client()
        testUser = {
            'username': 'TestTokenUser',
            'password': 'TestTokenUser1234!'
        }
        registerResponse = testClient.post('/register', json=testUser)
        self.assertEqual(registerResponse.status_code, HTTPStatus.OK)

        testData = {'data': 'test'}
        unauthorizedResponse = testClient.post('/testing/resource', json=testData)
        self.assertEqual(unauthorizedResponse.status_code, HTTPStatus.FORBIDDEN)

        loginResponse = testClient.post('/login', json=testUser)
        self.assertEqual(loginResponse.status_code, HTTPStatus.OK)

        testData = {'data': 'test'}
        testingResponse = testClient.post('/testing/resource', json=testData)
        self.assertEqual(testingResponse.status_code, HTTPStatus.OK)

        logoutResponse = testClient.post('logout')
        self.assertEqual(logoutResponse.status_code, HTTPStatus.OK)

        afterLogoutResponse = testClient.post('/testing/resource', json=testData)
        self.assertEqual(afterLogoutResponse.status_code, HTTPStatus.FORBIDDEN)
