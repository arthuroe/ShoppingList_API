from flask import Flask, jsonify, abort, make_response, request, url_for, render_template
from app import app
from app.models import db, User, ShoppingList, Item, BlacklistToken
from flask_httpauth import HTTPBasicAuth
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import os
import datetime
from app.auth.views import auth


auth = HTTPBasicAuth()
postgres_local_base = 'postgresql://arthuroe:dbadmin@localhost/'
database_name = 'shoppinglist'

app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', postgres_local_base + database_name)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'cronica!r1m'
db.init_app(app)


def token_required(f):
    @wraps(f)
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
            return "Expired token. Please login to get a new token"
        except jwt.InvalidTokenError:
            # the token is invalid, return an error string
            return jsonify({'message': 'Invalid token. Please register or login'}), 403
        return f(current_user, *args, **kwargs)
    return wrap

# decorator used to allow cross origin requests
@app.after_request
def apply_cross_origin_header(response):
    response.headers['Access-Control-Allow-Origin'] = '*'

    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET,HEAD,OPTIONS," \
                                                       "POST,PUT,DELETE"
    response.headers["Access-Control-Allow-Headers"] = "Access-Control-Allow-" \
        "Headers, Origin,Accept, X-Requested-With, Content-Type, " \
        "Access-Control-Request-Method, Access-Control-Request-Headers," \
        "Access-Control-Allow-Origin, Authorization"

    return response

@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)


@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 403)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/shoppinglists/<list_id>', methods=['PUT'])
def edit_list(list_id):
    data = request.get_json()
    lists = ShoppingList.query.filter_by(id=list_id).first()

    if not lists:
        return jsonify({'message': 'No item'}), 404
    lists.name = data['name']
    db.session.commit()

    return jsonify({'message': 'Item updated'}), 201



@app.route('/shoppinglists', methods=['GET'])
@token_required
def get_all_lists(current_user):
    name = request.args.get('q', '')
    limit = request.args.get('limit', 5, type=int)
    page = request.args.get('page', 1, type=int)
    user_lists = []
    if name:
        lists = ShoppingList.query.filter_by(user_id=current_user, name=name).all()
        for li in lists:
            user_lists.append({
                "name": li.name,
                "id": li.id
            })
        return jsonify({'lists': user_lists}), 200
    if limit:
       lists = ShoppingList.query.paginate(page,limit,False).items
       for li in lists:
            user_lists.append({
                "name": li.name,
                "id": li.id
            })
    else:
        all_lists = ShoppingList.query.filter_by(user_id=current_user).all()
        for li in all_lists:
            user_lists.append({
                "name": li.name,
                "id": li.id
            })

    return jsonify({'all_lists': user_lists}), 200


@app.route('/shoppinglists/<list_id>', methods=['GET'])
@token_required
def get_single_list(current_user, list_id):
    lists = ShoppingList.query.filter_by(id=list_id).all()
    user_lists = []
    for li in lists:
        user_lists.append({
            "name": li.name,
            "id": li.id
        })
    if not lists:
        return jsonify({'message': 'No list found'}), 404

    return jsonify({'lists': user_lists}), 200


@app.route('/shoppinglists/<list_id>', methods=['DELETE'])
@token_required
def delete_list(current_user, list_id):
    lists = ShoppingList.query.filter_by(id=list_id).first()
    if not lists:
        return jsonify({'message': 'No item'}), 404
    db.session.delete(lists)
    db.session.commit()
    return jsonify({'message': 'list deleted'}), 201


@app.route('/shoppinglists/', methods=['POST'])
@token_required
def create_list(current_user):
    data = request.get_json()
    new = ShoppingList.query.filter_by(name=data['name']).first()
    if new:
        return jsonify({'message': 'list already exists'}), 202
    new_list = ShoppingList(name=data['name'], user_id=current_user)
    db.session.add(new_list)
    db.session.commit()

    return jsonify({'message': 'list added'}), 201


@app.route('/shoppinglists/<list_id>/items', methods=['POST'])
@token_required
def add_list_item(current_user, list_id):
    data = request.get_json()
    new = Item.query.filter_by(name=data['name']).first()
    if new:
        return jsonify({'message': 'Item already exists'}), 202
    new_item = Item(name=data['name'], shoppinglist_id=list_id)
    db.session.add(new_item)
    db.session.commit()

    return jsonify({'message': 'item added'}), 201


@app.route('/shoppinglists/<list_id>/items', methods=['GET'])
@token_required
def get_items(current_user, list_id):
    items = Item.query.filter_by(shoppinglist_id=list_id).all()
    list_items = []
    for item in items:
        list_items.append({
            "name": item.name,
            "id": item.id
        })

    return jsonify({'list items': list_items}), 200


@app.route('/shoppinglists/<list_id>/items/<item_id>', methods=['GET'])
@token_required
def get_single_item(current_user, list_id, item_id):
    items = Item.query.filter_by(id=item_id).all()
    list_items = []
    for item in items:
        list_items.append({
            "name": item.name,
            "id": item.id
        })

    return jsonify({'list items': list_items}), 200


@app.route('/shoppinglists/<list_id>/items/<item_id>', methods=['PUT'])
@token_required
def edit_list_item(current_user, list_id, item_id):
    data = request.get_json()
    items = Item.query.filter_by(id=item_id).first()
    if not items:
        return jsonify({'message': 'No item'}), 404
    items.name = data['name']
    db.session.commit()

    return jsonify({'message': 'item edited'}), 201


@app.route('/shoppinglists/<list_id>/items/<item_id>', methods=['DELETE'])
@token_required
def delete_list_item(current_user, list_id, item_id):
    items = Item.query.filter_by(id=item_id).first()
    if not items:
        return jsonify({'message': 'No item'}), 404
    db.session.delete(items)
    db.session.commit()

    return jsonify({'message': 'item deleted'}), 201


@app.route('/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data['email']
    user = User.query.filter_by(email=email).first()
    if not user:
        return make_response(jsonify({'message': 'No user information found'})), 404
    user.password = generate_password_hash(data['password'])

    db.session.commit()
    response = {'message': 'You have successfully changed your password.'}
    return make_response(jsonify(response)), 201


@app.route('/auth/logout', methods=['POST'])
@token_required
def logout(current_user):
        # get auth token
    if 'access-token' in request.headers:
        token = request.headers['access-token']
        # mark the token as blacklisted
        blacklist_token = BlacklistToken(token=token)
        try:
            # insert the token
            db.session.add(blacklist_token)
            db.session.commit()
            responseObject = {
                'status': 'success',
                'message': 'Successfully logged out.'
            }
            return make_response(jsonify(responseObject)), 200
        except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': 'Already logged Out'
            }
            return make_response(jsonify(responseObject)), 200
    else:
        responseObject = {
            'status': 'fail',
            'message': 'Provide a valid auth token.'
        }
        return make_response(jsonify(responseObject)), 403
