import os
import sys
sys.path.append('..')
import json
import unittest
import tempfile
from base64 import b64encode
from app.models import db, User
from app import app


class AuthTestCase(unittest.TestCase):
    """Testcases for the Users class"""

    def setUp(self):
        self.db_fd, app.config['DATABASE'] = tempfile.mkstemp()
        app.testing = True
        self.app = app.test_client()
        self.user_data = {"name": "test", "email": "test@gmail.com", "password": "test"}
        with app.app_context():
            db.drop_all()
            db.create_all()

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(app.config['DATABASE'])

    def test_registration(self):
        """Test user registration works correcty."""
        with self.app:
            response = self.app.post('/auth/register', data=json.dumps(self.user_data),
                                     content_type='application/json')
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['message'] == 'Successfully registered.')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 201)

    def test_register_with_already_registered_user(self):
        """ Test registration with already registered email"""
        res = self.app.post('/auth/register', data=json.dumps(self.user_data),
                            content_type='application/json')
        self.assertEqual(res.status_code, 201)
        response = self.app.post('/auth/register', data=json.dumps(self.user_data),
                                 content_type='application/json')
        self.assertEqual(response.status_code, 202)
        # get the results returned in json format
        data = json.loads(response.data.decode())
        self.assertTrue(data['status'] == 'fail')
        self.assertTrue(
            data['message'] == 'User already exists. Please Log in.')
        self.assertTrue(response.content_type == 'application/json')
        self.assertEqual(response.status_code, 202)

    def test_user_login(self):
        """Test registered user can login."""
        res = self.app.post('/auth/register', data=json.dumps(self.user_data),
                            content_type='application/json')
        self.assertEqual(res.status_code, 201)
        login_res = self.app.post('/auth/login', data=json.dumps(self.user_data),
                                  content_type='application/json')

        data = json.loads(login_res.data.decode())
        # Test that the response contains success message
        self.assertEqual(data['message'], "You logged in successfully.")
        self.assertEqual(login_res.status_code, 200)
        self.assertTrue(data['access_token'])

    def test_non_registered_user_login(self):
        """Test non registered users cannot login."""
        res = self.app.post('/auth/login', data=json.dumps(self.user_data),
                            content_type='application/json')
        data = json.loads(res.data.decode())

        self.assertEqual(res.status_code, 401)
        self.assertEqual(data['message'], "User does not exist.")

    def test_user_can_reset_password(self):
        """Test user can reset password."""
        res = self.app.post('/auth/register', data=json.dumps(self.user_data),
                            content_type='application/json')
        self.assertEqual(res.status_code, 201)
        rese = self.app.post('/auth/reset-password', data=json.dumps({"email": "test@gmail.com", "password": "new"}),
                             content_type='application/json')

        data = json.loads(rese.data.decode())
        self.assertEqual(data['message'], "You have successfully changed your password.")
        self.assertEqual(rese.status_code, 201)

    def test_non_user_cannot_reset_password(self):
        """Test non registered user cannot reset password."""
        res = self.app.post('/auth/register', data=json.dumps(self.user_data),
                            content_type='application/json')
        self.assertEqual(res.status_code, 201)
        rese = self.app.post('/auth/reset-password', data=json.dumps({"email": "none@gmail.com", "password": "new"}),
                             content_type='application/json')

        data = json.loads(rese.data.decode())
        self.assertEqual(data['message'], "No user information found")
        self.assertEqual(rese.status_code, 404)

    def test_user_logout(self):
        """Test registered user can logout."""
        res = self.app.post('/auth/register', data=json.dumps(self.user_data),
                            content_type='application/json')
        self.assertEqual(res.status_code, 201)
        login_res = self.app.post(
            '/auth/login', data=json.dumps(self.user_data), content_type='application/json')
        access_token = json.loads(login_res.data.decode())['access_token']
        logout_res = self.app.post(
            '/auth/logout', headers={'Content-Type': 'application/json', 'access-token': access_token})
        data = json.loads(logout_res.data.decode())
        # Test that the response contains success message
        self.assertEqual(data['message'], "Successfully logged out.")
        self.assertEqual(login_res.status_code, 200)
        self.assertTrue(data['status'], 'success')


if __name__ == '__main__':
    unittest.main()
