import os
import json
import unittest
import tempfile
from base64 import b64encode
from run import app, db


class UsersTestCase(unittest.TestCase):
    """Testcases for the Users class"""

    def setUp(self):
        self.db_fd, app.config['DATABASE'] = tempfile.mkstemp()
        app.testing = True
        self.app = app.test_client()
        self.user = {"username": "flacode", "password": "flavia", "email": "fnshem@gmail.com"}
        self.shopping_list = {"name": "bakery", "user_id": 1, "due_date": "2017-08-17"}
        self.item = {"name": "sweetpotatoes", "quantity": 6,
                     "bought_from": "kalerwe", "status": "false"}
        with app.app_context():
            db.drop_all()
            db.create_all()

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(app.config['DATABASE'])

    def test_user_account_creation(self):
        """Test user login"""
        result = self.app.post('/auth/register', data=json.dumps(self.user),
                               headers={'Content-Type': 'application/json'})
        self.assertEqual(result.status_code, 201)

    def test_user_account_creation_with_existing_account(self):
        """Test user account creation with an exixting username"""
        self.app.post('/auth/register', data=json.dumps(self.user),
                      headers={'Content-Type': 'application/json'})
        result = self.app.post('/auth/register', data=json.dumps(self.user),
                               headers={'Content-Type': 'application/json'})
        self.assertEqual(result.status_code, 409)

    def test_user_login_with_correct_password(self):
        """Test user login with correct credentials"""
        self.app.post('/auth/register', data=json.dumps(self.user),
                      headers={'Content-Type': 'application/json'})
        user_pass = b64encode(b"flacode:flavia").decode("ascii")
        headers = {'Authorization': 'Basic %s' % user_pass}
        result = self.app.post('/auth/login', headers=headers)
        self.assertEqual(result.status_code, 200)
        self.assertIn('User logged in successfully', str(result.data))

    def test_user_login_with_incorrect_password(self):
        """Test user login with incorrect password"""
        self.app.post('/auth/register', data=json.dumps(self.user),
                      headers={'Content-Type': 'application/json'})
        user_pass = b64encode(b"flacode:123").decode("ascii")
        headers = {'Authorization': 'Basic %s' % user_pass}
        result = self.app.post('/auth/login', headers=headers)
        self.assertEqual(result.status_code, 401)
        self.assertIn('Invalid user credentials', str(result.data))

    def test_user_login_with_non_existing_account(self):
        """Test user login with a username that is not registered"""
        self.app.post('/auth/register', data=json.dumps(self.user),
                      headers={'Content-Type': 'application/json'})
        user_pass = b64encode(b"odette:123").decode("ascii")
        headers = {'Authorization': 'Basic %s' % user_pass}
        result = self.app.post('/auth/login', headers=headers)
        self.assertEqual(result.status_code, 401)
        self.assertIn('User does not exist', str(result.data))

    def test_reset_password(self):
        """Test user reset password"""
        self.app.post('/auth/register', data=json.dumps(self.user),
                      headers={'Content-Type': 'application/json'})
        reset = self.app.post('/auth/reset-password',
                              data=json.dumps({"username": "flacode",
                                               "password": "new_password"}),
                              headers={'Content-Type': 'application/json'})
        self.assertEqual(reset.status_code, 200)
        self.assertIn('You have successfully changed your password.', str(reset.data))
        user_pass = b64encode(b"flacode:new_password").decode("ascii")
        headers = {'Authorization': 'Basic %s' % user_pass}
        result = self.app.post('/auth/login', headers=headers)
        self.assertEqual(result.status_code, 200)

    def test_reset_password_with_non_existent_user(self):
        """Test user reset password"""
        self.app.post('/auth/register', data=json.dumps(self.user),
                      headers={'Content-Type': 'application/json'})
        reset = self.app.post('/auth/reset-password',
                              data=json.dumps({"username": "sammy",
                                               "password": "new_password"}),
                              headers={'Content-Type': 'application/json'})
        self.assertEqual(reset.status_code, 404)
        self.assertIn('No user information found', str(reset.data))

    def test_create_shopping_list_for_registered_user(self):
        """Test create shopping list for user"""
        self.app.post('/auth/register', data=json.dumps(self.user),
                      headers={'Content-Type': 'application/json'})
        result = self.app.post('/shoppinglists/', data=json.dumps(self.shopping_list),
                               headers={'Content-Type': 'application/json'})
        self.assertEqual(result.status_code, 201)
        self.assertIn('Shopping list created.', str(result.data))

    def test_create_shopping_list_for_unregistered_user(self):
        """Test create shopping list for unregisterd user"""
        result = self.app.post('/shoppinglists/', data=json.dumps(self.shopping_list),
                               headers={'Content-Type': 'application/json'})
        self.assertEqual(result.status_code, 404)
        self.assertIn('User does not exist.', str(result.data))

    def test_view_all_shopping_lists(self):
        """Test to view all shopping lists"""
        result = self.app.get('/shoppinglists/')
        self.assertEqual(result.status_code, 200)
        self.assertIn('No shopping lists created yet.', str(result.data))
        self.app.post('/auth/register', data=json.dumps(self.user),
                      headers={'Content-Type': 'application/json'})
        self.app.post('/shoppinglists/', data=json.dumps(self.shopping_list),
                      headers={'Content-Type': 'application/json'})
        shopping_lists = self.app.get('/shoppinglists/')
        self.assertIn('shopping_lists', str(shopping_lists.data))

    def test_view_on_shopping_list(self):
        """Test if user can view saved shopping list"""
        # if shopping list is not saved in the database
        result = self.app.get('/shoppinglists/1')
        self.assertEqual(result.status_code, 404)
        self.assertIn('Shopping list can not be found', str(result.data))
        self.app.post('/auth/register', data=json.dumps(self.user),
                      headers={'Content-Type': 'application/json'})
        self.app.post('/shoppinglists/', data=json.dumps(self.shopping_list),
                      headers={'Content-Type': 'application/json'})
        shopping_list = self.app.get('/shoppinglists/1')
        self.assertEqual(shopping_list.status_code, 200)
        self.assertIn('shopping list', str(shopping_list.data))

    def test_update_shopping_list(self):
        # if shopping list is not saved in the database
        result = self.app.put('/shoppinglists/1', data=json.dumps({"name": "new_name"}),
                              headers={'Content-Type': 'application/json'})
        self.assertEqual(result.status_code, 404)
        self.assertIn('Shopping list can not be found', str(result.data))
        self.app.post('/auth/register', data=json.dumps(self.user),
                      headers={'Content-Type': 'application/json'})
        self.app.post('/shoppinglists/', data=json.dumps(self.shopping_list),
                      headers={'Content-Type': 'application/json'})
        update_shopping_list = self.app.put('/shoppinglists/1', data=json.dumps({"name": "new_name"}),
                                            headers={'Content-Type': 'application/json'})
        self.assertEqual(update_shopping_list.status_code, 200)
        self.assertIn('Shopping list has been updated', str(update_shopping_list.data))

    def test_delete_shopping_list(self):
        """Test to delete shopping list from the database"""
        result = self.app.delete('/shoppinglists/1')
        self.assertEqual(result.status_code, 404)
        self.assertIn('Shopping list can not be found', str(result.data))
        self.app.post('/auth/register', data=json.dumps(self.user),
                      headers={'Content-Type': 'application/json'})
        self.app.post('/shoppinglists/', data=json.dumps(self.shopping_list),
                      headers={'Content-Type': 'application/json'})
        deleted = self.app.delete('/shoppinglists/1')
        self.assertEqual(deleted.status_code, 200)
        self.assertIn('Shopping list successfully deleted', str(deleted.data))

    def test_add_item_to_shopping_list(self):
        """Test to add items to a shopping list"""
        result = self.app.post('/shoppinglists/1/items/', data=json.dumps(self.item),
                               headers={'Content-Type': 'application/json'})
        self.assertEqual(result.status_code, 404)
        self.assertIn('Shopping list can not be found to add items', str(result.data))
        # create user, shopping list and add items to shopping list
        self.app.post('/auth/register', data=json.dumps(self.user),
                      headers={'Content-Type': 'application/json'})
        self.app.post('/shoppinglists/', data=json.dumps(self.shopping_list),
                      headers={'Content-Type': 'application/json'})
        item = self.app.post('/shoppinglists/1/items/', data=json.dumps(self.item),
                             headers={'Content-Type': 'application/json'})
        self.assertEqual(item.status_code, 201)
        self.assertIn('Item added to shopping list', str(item.data))

    def test_update_item_in_shopping_list(self):
        """Test update item in shopping list"""
        # if shopping list is not saved in the database
        result = self.app.put('/shoppinglists/1/items/1', data=json.dumps({"name": "new_name"}),
                              headers={'Content-Type': 'application/json'})
        self.assertEqual(result.status_code, 404)
        self.assertIn('Shopping list can not be found to update items', str(result.data))
        # create user, shopping list
        self.app.post('/auth/register', data=json.dumps(self.user),
                      headers={'Content-Type': 'application/json'})
        self.app.post('/shoppinglists/', data=json.dumps(self.shopping_list),
                      headers={'Content-Type': 'application/json'})
        # update item that is not in the shopping list
        item = self.app.put('/shoppinglists/1/items/1', data=json.dumps({"name": "new_name"}),
                            headers={'Content-Type': 'application/json'})
        self.assertEqual(item.status_code, 404)
        self.assertIn('Item can not be found in shopping list', str(item.data))
        # add item to shopping list
        self.app.post('/shoppinglists/1/items/', data=json.dumps(self.item),
                      headers={'Content-Type': 'application/json'})
        # update item in shopping list
        update_item = self.app.put('/shoppinglists/1/items/1', data=json.dumps({"name": "new_name"}),
                                   headers={'Content-Type': 'application/json'})
        self.assertEqual(update_item.status_code, 200)
        self.assertIn('Item updated', str(update_item.data))

    def test_view_items_in_shopping_list(self):
        # create user
        self.app.post('/auth/register', data=json.dumps(self.user),
                      headers={'Content-Type': 'application/json'})
        shopping_list = self.app.get('/shoppinglists/1/items/')
        self.assertEqual(shopping_list.status_code, 404)
        self.assertIn('Shopping list can not be found', str(shopping_list.data))
        # create shopping list
        self.app.post('/shoppinglists/', data=json.dumps(self.shopping_list),
                      headers={'Content-Type': 'application/json'})
        shopping_list = self.app.get('/shoppinglists/1/items/')
        self.assertEqual(shopping_list.status_code, 200)
        self.assertIn('Shopping list is empty', str(shopping_list.data))
        # add item
        self.app.post('/shoppinglists/1/items/', data=json.dumps(self.item),
                      headers={'Content-Type': 'application/json'})
        shopping_list = self.app.get('/shoppinglists/1/items/')
        self.assertEqual(shopping_list.status_code, 200)
        self.assertIn('Items', str(shopping_list.data))

    def test_delete_item_from_shopping_list(self):
        self.app.post('/auth/register', data=json.dumps(self.user),
                      headers={'Content-Type': 'application/json'})
        deleted = self.app.delete('/shoppinglists/1/items/1')
        self.assertEqual(deleted.status_code, 404)
        self.assertIn('Shopping list can not be found to update items', str(deleted.data))
        self.app.post('/shoppinglists/', data=json.dumps(self.shopping_list),
                      headers={'Content-Type': 'application/json'})
        deleted = self.app.delete('/shoppinglists/1/items/1')
        self.assertEqual(deleted.status_code, 404)
        self.assertIn('Item can not be found in shopping list', str(deleted.data))
        self.app.post('/shoppinglists/1/items/', data=json.dumps(self.item),
                      headers={'Content-Type': 'application/json'})
        deleted = self.app.delete('/shoppinglists/1/items/1')
        self.assertEqual(deleted.status_code, 200)
        self.assertIn('Item successfully deleted from shopping list', str(deleted.data))
