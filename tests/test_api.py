import os
import sys
sys.path.append('..')
import json
import unittest
import tempfile
from base64 import b64encode
from app.models import db, User
from app import app
import pytest


class AuthTestCase(unittest.TestCase):
    """Testcases for the Users class"""

    def setUp(self):
        self.db_fd, app.config['DATABASE'] = tempfile.mkstemp()
        app.testing = True
        self.app = app.test_client()
        self.shopping_list = {"name": "test_list"}
        self.item = {"name": "test_item"}
        with app.app_context():
            db.drop_all()
            db.create_all()

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(app.config['DATABASE'])

    def register_user(self, name='test', email="test@gmail.com", password="test1234"):
        """This helper method helps register a test user."""
        user_data = {'name': name,
                     'email': email,
                     'password': password
                     }
        return self.app.post('/api/v1/auth/register', data=json.dumps(user_data), content_type='application/json')

    def login_user(self, email="test@gmail.com", password="test1234"):
        """This helper method helps log in a test user."""
        user_data = {
            'email': email,
            'password': password
        }
        return self.app.post('/api/v1/auth/login', data=json.dumps(user_data), content_type='application/json')

    def test_create_shopping_list_for_registered_user(self):
        """Test create shopping list for user"""
        with self.app:
            self.register_user()
            result = self.login_user()
            access_token = json.loads(result.data.decode())['access_token']
            result = self.app.post('/api/v1/shoppinglists/', data=json.dumps(self.shopping_list),
                                   headers={'Content-Type': 'application/json', 'access-token': access_token})
            self.assertEqual(result.status_code, 201)
            self.assertIn('list added', str(result.data))

    def test_create_shopping_list_for_unregistered_user(self):
        """Test create shopping list for unregisterd user"""
        result = self.app.post('/api/v1/shoppinglists/', data=json.dumps(self.shopping_list),
                               headers={'Content-Type': 'application/json', 'access-token': ''})
        self.assertEqual(result.status_code, 403)
        self.assertIn('Token is missing!', str(result.data))

    def test_view_all_shopping_lists(self):
        """Test to view all shopping lists"""
        self.register_user()
        result = self.login_user()
        access_token = json.loads(result.data.decode())['access_token']

        res = self.app.post('/api/v1/shoppinglists/', data=json.dumps(self.shopping_list),
                            headers={'Content-Type': 'application/json', 'access-token': access_token})
        self.assertEqual(res.status_code, 201)

        get_result = self.app.get('/api/v1/shoppinglists', headers={'Content-Type': 'application/json',
                                                                    'access-token': access_token})
        self.assertEqual(get_result.status_code, 200)

    def test_search_shopping_lists(self):
        """Test search shopping lists"""
        self.register_user()
        result = self.login_user()
        access_token = json.loads(result.data.decode())['access_token']

        res = self.app.post('/api/v1/shoppinglists/', data=json.dumps(self.shopping_list),
                            headers={'Content-Type': 'application/json', 'access-token': access_token})
        self.assertEqual(res.status_code, 201)

        get_result = self.app.get('/api/v1/shoppinglists?q=test_list', headers={'Content-Type': 'application/json',
                                                                                'access-token': access_token})
        self.assertEqual(get_result.status_code, 200)

    def test_view_one_shopping_list(self):
        """Test if user can view one saved shopping list"""
        self.register_user()
        result = self.login_user()
        access_token = json.loads(result.data.decode())['access_token']

        res = self.app.post('/api/v1/shoppinglists/', data=json.dumps(self.shopping_list),
                            headers={'Content-Type': 'application/json', 'access-token': access_token})
        self.assertEqual(res.status_code, 201)

        get_result = self.app.get('/api/v1/shoppinglists/1', headers={'Content-Type': 'application/json',
                                                                      'access-token': access_token})
        self.assertEqual(get_result.status_code, 200)

    def test_update_shopping_list(self):
        """Test if user can update saved shopping list"""
        self.register_user()
        result = self.login_user()
        access_token = json.loads(result.data.decode())['access_token']
        res = self.app.post('/api/v1/shoppinglists/', data=json.dumps(self.shopping_list),
                            headers={'Content-Type': 'application/json', 'access-token': access_token})
        self.assertEqual(res.status_code, 201)

        get_result = self.app.get('/api/v1/shoppinglists/1', headers={'Content-Type': 'application/json',
                                                                      'access-token': access_token})
        self.assertEqual(get_result.status_code, 200)

        update_res = self.app.put('/api/v1/shoppinglists/1', data=json.dumps({"name": "new_name"}),
                                  headers={'Content-Type': 'application/json', 'access-token': access_token})

        self.assertEqual(update_res.status_code, 200)

    def test_delete_shopping_list(self):
        """Test to delete shopping list from the database"""
        self.register_user()
        result = self.login_user()
        access_token = json.loads(result.data.decode())['access_token']
        res = self.app.post('/api/v1/shoppinglists/', data=json.dumps(self.shopping_list),
                            headers={'Content-Type': 'application/json', 'access-token': access_token})
        self.assertEqual(res.status_code, 201)

        get_result = self.app.get('/api/v1/shoppinglists/1', headers={'Content-Type': 'application/json',
                                                                      'access-token': access_token})
        self.assertEqual(get_result.status_code, 200)
        del_result = self.app.delete('/api/v1/shoppinglists/1', headers={'Content-Type': 'application/json',
                                                                         'access-token': access_token})
        self.assertEqual(del_result.status_code, 200)

    def test_add_item_to_shopping_list(self):
        """Test to add items to a shopping list"""
        self.register_user()
        result = self.login_user()
        access_token = json.loads(result.data.decode())['access_token']
        res = self.app.post('/api/v1/shoppinglists/', data=json.dumps(self.shopping_list),
                            headers={'Content-Type': 'application/json', 'access-token': access_token})
        self.assertEqual(res.status_code, 201)

        get_result = self.app.get('/api/v1/shoppinglists/1', headers={'Content-Type': 'application/json',
                                                                      'access-token': access_token})
        self.assertEqual(get_result.status_code, 200)
        item = self.app.post('/api/v1/shoppinglists/1/items', data=json.dumps(self.item),
                             headers={'Content-Type': 'application/json', 'access-token': access_token})
        self.assertEqual(item.status_code, 201)

    def test_update_item_in_shopping_list(self):
        """Test update item in shopping list"""
        self.register_user()
        result = self.login_user()
        access_token = json.loads(result.data.decode())['access_token']
        res = self.app.post('/api/v1/shoppinglists/', data=json.dumps(self.shopping_list),
                            headers={'Content-Type': 'application/json', 'access-token': access_token})
        self.assertEqual(res.status_code, 201)

        get_result = self.app.get('/api/v1/shoppinglists/1', headers={'Content-Type': 'application/json',
                                                                      'access-token': access_token})
        self.assertEqual(get_result.status_code, 200)
        item = self.app.post('/api/v1/shoppinglists/1/items', data=json.dumps(self.item),
                             headers={'Content-Type': 'application/json', 'access-token': access_token})
        self.assertEqual(item.status_code, 201)
        update_item = self.app.put('/api/v1/shoppinglists/1/items/1', data=json.dumps({"name": "new_name"}),
                                   headers={'Content-Type': 'application/json', 'access-token': access_token})
        self.assertEqual(update_item.status_code, 200)

    def test_view_items_in_shopping_list(self):
        """Test view items in shopping list"""
        self.register_user()
        result = self.login_user()
        access_token = json.loads(result.data.decode())['access_token']
        res = self.app.post('/api/v1/shoppinglists/', data=json.dumps(self.shopping_list),
                            headers={'Content-Type': 'application/json', 'access-token': access_token})
        self.assertEqual(res.status_code, 201)

        get_result = self.app.get('/api/v1/shoppinglists/1', headers={'Content-Type': 'application/json',
                                                                      'access-token': access_token})
        self.assertEqual(get_result.status_code, 200)
        item = self.app.post('/api/v1/shoppinglists/1/items', data=json.dumps(self.item),
                             headers={'Content-Type': 'application/json', 'access-token': access_token})
        self.assertEqual(item.status_code, 201)
        view_item = self.app.get('/api/v1/shoppinglists/1/items',
                                 headers={'Content-Type': 'application/json', 'access-token': access_token})
        self.assertEqual(view_item.status_code, 200)

    def test_delete_item_from_shopping_list(self):
        """Test update item in shopping list"""
        self.register_user()
        result = self.login_user()
        access_token = json.loads(result.data.decode())['access_token']
        res = self.app.post('/api/v1/shoppinglists/', data=json.dumps(self.shopping_list),
                            headers={'Content-Type': 'application/json', 'access-token': access_token})
        self.assertEqual(res.status_code, 201)

        get_result = self.app.get('/api/v1/shoppinglists/1', headers={'Content-Type': 'application/json',
                                                                      'access-token': access_token})
        self.assertEqual(get_result.status_code, 200)
        item = self.app.post('/api/v1/shoppinglists/1/items', data=json.dumps(self.item),
                             headers={'Content-Type': 'application/json', 'access-token': access_token})
        self.assertEqual(item.status_code, 201)
        delete_item = self.app.delete(
            '/api/v1/shoppinglists/1/items/1', headers={'Content-Type': 'application/json', 'access-token': access_token})
        self.assertEqual(delete_item.status_code, 200)


if __name__ == '__main__':
    unittest.main()
