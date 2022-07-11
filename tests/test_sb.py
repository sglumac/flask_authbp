import unittest

from tests.utility import create_sb_app


class TestSessionBased(unittest.TestCase):
    def setUp(self):
        self.app = create_sb_app('sb_specific_testing_app')

    def test_accepted_authorization(self):
        testClient = self.app.test_client()
        testUser = {
            'username': 'TestTokenUser',
            'password': 'TestTokenUser1234!'
        }
        registerResponse = testClient.post('/register', json=testUser)
        self.assertEqual(registerResponse.status_code, 200)
        loginResponse = testClient.post('/login', json=testUser)
        self.assertEqual(loginResponse.status_code, 200)

        testData = {'data': 'test'}
        testingResponse = testClient.post('/testing/resource', json=testData)
        self.assertEqual(testingResponse.status_code, 200)
