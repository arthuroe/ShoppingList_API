"""
views.py
"""

import os
from functools import wraps
import jwt
from flask import jsonify, make_response, request, render_template
from app import app
from app.models import db, User, ShoppingList, Item, BlacklistToken
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash
from app.auth.views import auth, require_fields


auth = HTTPBasicAuth()
postgres_local_base = 'postgresql://arthuroe:dbadmin@localhost/'
database_name = 'shoppinglist'

app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', postgres_local_base + database_name)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'cronica!r1m'
db.init_app(app)


def token_required(function):
    """
    This checks for authentication token
    """
    @wraps(function)
    def wrap(*args, **kwargs):
        token = None
        if 'access-token' in request.headers:
            token = request.headers['access-token']
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        is_blacklisted_token = BlacklistToken.check_blacklist(token)
        if is_blacklisted_token:
            return jsonify({'message': 'Token blacklisted. Please log in again.'}), 403

        try:
            # try to decode the token using our SECRET variable
            payload = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = payload['sub']
            # return current_user
        except jwt.ExpiredSignatureError:
            # the token is expired, return an error string
            return jsonify({"messge": "Expired token. Please login to get a new token"}), 403
        except jwt.InvalidTokenError:
            # the token is invalid, return an error string
            return jsonify({'message': 'Invalid token. Please register or login'}), 403
        return function(current_user, *args, **kwargs)
    return wrap

# decorator used to allow cross origin requests


@app.after_request
def apply_cross_origin_header(response):
    """
    This function enables CORS
    """
    response.headers['Access-Control-Allow-Origin'] = '*'

    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET,HEAD,OPTIONS," \
                                                       "POST,PUT,DELETE"
    response.headers["Access-Control-Allow-Headers"] = "Access-Control-Allow-" \
        "Headers, Origin,Accept, X-Requested-With, Content-Type, " \
        "Access-Control-Request-Method, Access-Control-Request-Headers," \
        "Access-Control-Allow-Origin, Authorization"

    return response


@app.errorhandler(404)
def not_found(error):
    """
    This function handles 404 errors
    """
    return make_response(jsonify({'error': 'Not found'}), 404)


@auth.error_handler
def unauthorized():
    """
    This function  handles 403 errors
    """
    return make_response(jsonify({'error': 'Unauthorized access'}), 403)


@app.route('/')
def index():
    """
    This route enables a user access API documemntattion
    """
    return render_template('index.html')


@app.route('/shoppinglists/<list_id>', methods=['PUT'])
@require_fields('name')
def edit_list(list_id):
    """
    This route enables a user to update a shopping list
    """
    data = request.get_json()
    if not data['name']:
        return make_response(jsonify({"message": "Name field required"})), 400
    list_to_edit = ShoppingList.query.filter_by(id=list_id).first()

    if not list_to_edit:
        return jsonify({'message': 'No item'}), 404
    list_to_edit.name = data['name']
    db.session.commit()

    return jsonify({'message': 'Item updated'}), 200


@app.route('/shoppinglists', methods=['GET'])
@token_required
def get_all_lists(current_user):
    """
    This route enables a user to view all shoppinglists
    """
    name = request.args.get('q', '')
    limit = request.args.get('limit', None, type=int)
    page = request.args.get('page', 1, type=int)
    user_lists = []
    if name:
        shopping_list = ShoppingList.query.filter_by(user_id=current_user, name=name).all()
        user_lists = [i.serialize for i in shopping_list]
        return jsonify({'shoppinglist': user_lists}), 200
    if limit:
        shoppinglists = ShoppingList.query.filter_by(
            user_id=current_user).paginate(page, limit, False).items
        user_lists = [i.serialize for i in shoppinglists]
    else:
        all_shoppinglists = ShoppingList.query.filter_by(user_id=current_user).all()
        user_lists = [i.serialize for i in all_shoppinglists]

    return jsonify({'shoppinglists': user_lists}), 200


@app.route('/shoppinglists/<list_id>', methods=['GET'])
@token_required
def get_single_list(current_user, list_id):
    """
    This route enables a user to view a single shoppinglist
    """
    lists = ShoppingList.query.filter_by(id=list_id).all()
    user_lists = []
    user_lists = [i.serialize for i in lists]
    if not lists:
        return jsonify({'message': 'No list found'}), 404

    return jsonify({'shoppinglist': user_lists}), 200


@app.route('/shoppinglists/<list_id>', methods=['DELETE'])
@token_required
def delete_list(current_user, list_id):
    """
    This route enables a user to delete a shoppinglist
    """
    list_to_delete = ShoppingList.query.filter_by(id=list_id).first()
    if not list_to_delete:
        return jsonify({'message': 'No item'}), 404
    db.session.delete(list_to_delete)
    db.session.commit()
    return jsonify({'message': 'list deleted'}), 200


@app.route('/shoppinglists/', methods=['POST'])
@token_required
@require_fields('name')
def create_list(current_user):
    """
    This route enables a user to create a shoppinglist
    """
    data = request.get_json()
    if not data['name']:
        return make_response(jsonify({"message": "Name field required"})), 400
    new_shoppinglist = ShoppingList.query.filter_by(name=data['name']).first()
    if new_shoppinglist:
        return jsonify({'message': 'list already exists'}), 400
    new_list = ShoppingList(name=data['name'], user_id=current_user)
    db.session.add(new_list)
    db.session.commit()

    return jsonify({'message': 'list added'}), 201


@app.route('/shoppinglists/<list_id>/items', methods=['POST'])
@token_required
@require_fields('name')
def add_list_item(current_user, list_id):
    """
    This route enables a user to create a shoppinglist
    """
    data = request.get_json()
    if not data['name']:
        return make_response(jsonify({"message": "Name field required"})), 400
    new_shoppinglist = Item.query.filter_by(name=data['name']).first()
    if new_shoppinglist:
        return jsonify({'message': 'Item already exists'}), 400
    new_item = Item(name=data['name'], shoppinglist_id=list_id)
    db.session.add(new_item)
    db.session.commit()

    return jsonify({'message': 'item added'}), 201


@app.route('/shoppinglists/<list_id>/items', methods=['GET'])
@token_required
def get_items(current_user, list_id):
    """
    This route enables a user to view a shoppinglist's items
    """
    shoppinglist_items = Item.query.filter_by(shoppinglist_id=list_id).all()
    list_items = []
    list_items = [item.serialize for item in shoppinglist_items]

    return jsonify({'shoppinglist items': list_items}), 200


@app.route('/shoppinglists/<list_id>/items/<item_id>', methods=['GET'])
@token_required
def get_single_item(current_user, list_id, item_id):
    """
    This route enables a user to view a single item from a shoppinglist
    """
    shoppinglist_item = Item.query.filter_by(id=item_id).all()
    list_item = []
    list_item = [item.serialize for item in shoppinglist_item]
    return jsonify({'shoppinglist item': list_item}), 200


@app.route('/shoppinglists/<list_id>/items/<item_id>', methods=['PUT'])
@token_required
@require_fields('name')
def edit_list_item(current_user, list_id, item_id):
    """
    This route enables a user to update a shoppinglist's item
    """
    data = request.get_json()
    if not data['name']:
        return make_response(jsonify({"message": "Name field required"})), 400
    item_to_edit = Item.query.filter_by(id=item_id).first()
    if not item_to_edit:
        return jsonify({'message': 'No item'}), 404
    item_to_edit.name = data['name']
    db.session.commit()

    return jsonify({'message': 'item edited'}), 200


@app.route('/shoppinglists/<list_id>/items/<item_id>', methods=['DELETE'])
@token_required
def delete_list_item(current_user, list_id, item_id):
    """
    This route enables a user to delete a shoppinglist's item
    """
    item_to_delete = Item.query.filter_by(id=item_id).first()
    if not item_to_delete:
        return jsonify({'message': 'No item'}), 404
    db.session.delete(item_to_delete)
    db.session.commit()

    return jsonify({'message': 'item deleted'}), 200


@app.route('/auth/reset-password', methods=['POST'])
@require_fields('email', 'password')
def reset_password():
    """
    This route enables a user to reset their passowrd
    """
    data = request.get_json()
    email = data['email']
    user = User.query.filter_by(email=email).first()
    if not user:
        return make_response(jsonify({'message': 'No user information found'})), 404
    user.password = generate_password_hash(data['password'])

    db.session.commit()
    response = {'message': 'You have successfully changed your password.'}
    return make_response(jsonify(response)), 200


@app.route('/auth/logout', methods=['POST'])
@token_required
def logout(current_user):
    """
    This route enables a user to logout
    """
    if 'access-token' in request.headers:
        token = request.headers['access-token']
        # mark the token as blacklisted
        blacklist_token = BlacklistToken(token=token)
        try:
            # insert the token
            db.session.add(blacklist_token)
            db.session.commit()
            response = {
                'status': 'success',
                'message': 'Successfully logged out.'
            }
            return make_response(jsonify(response)), 200
        except Exception as e:
            response = {
                'status': 'fail',
                'message': 'Already logged Out'
            }
            return make_response(jsonify(response)), 400
    else:
        response = {
            'status': 'fail',
            'message': 'Provide a valid auth token.'
        }
        return make_response(jsonify(response)), 403
