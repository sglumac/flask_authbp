import unittest

from tests.utility import create_sb_app


class TestSessionBased(unittest.TestCase):
    def setUp(self):
        app = create_sb_app('sb_specific_testing_app')
        self._testClient = app.test_client()

    def test_accepted_authorization(self):
        testUser = {
            'username': 'TestTokenUser',
            'password': 'TestTokenUser1234!'
        }
        registerResponse = self._testClient.post('/register', json=testUser)
        self.assertEqual(registerResponse.status_code, 200)
        loginResponse = self._testClient.post('/login', json=testUser)
        self.assertEqual(loginResponse.status_code, 200)

        testData = {'data': 'test'}
        testingResponse = self._testClient.post('/testing/resource', json=testData)
        self.assertEqual(testingResponse.status_code, 200)