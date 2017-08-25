from flask import Flask, jsonify, abort, make_response, request, url_for
from models.models import db, User, ShoppingList, Item
from flask_httpauth import HTTPBasicAuth
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime

app = Flask(__name__)
auth = HTTPBasicAuth()

app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://arthur:dbadmin@localhost/shoplists'
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
            return jsonify({'message', 'Token is missing!'})
        try:
            # try to decode the token using our SECRET variable
            payload = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(id=payload['sub']).first()
            # return current_user
        except jwt.ExpiredSignatureError:
            # the token is expired, return an error string
            return "Expired token. Please login to get a new token"
        except jwt.InvalidTokenError:
            # the token is invalid, return an error string
            return "Invalid token. Please register or login"
        return f(current_user, *args, **kwargs)
    return wrap


@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)


@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 403)


def make_public_task(task):
    new_task = {}
    for field in task:
        if field == 'id':
            new_task['uri'] = url_for('get_task', task_id=task['id'], _external=True)
        else:
            new_task[field] = task[field]
    return new_task


@app.route('/shoppinglists/<list_id>', methods=['PUT'])
def edit_list(list_id):
    data = request.get_json()
    lists = ShoppingList.query.filter_by(id=list_id).first()

    if not lists:
        return jsonify({'message': 'No item'})
    lists.name = data['name']
    db.session.commit()

    return jsonify({'message': 'Item updated'})


@app.route('/shoppinglists/', methods=['GET'])
@token_required
def get_all_lists(current_user):
    lists = ShoppingList.query.all()
    user_lists = []
    for li in lists:
        user_lists.append({
            "name": li.name,
            "id": li.id
        })

    return jsonify({'lists': user_lists}), 201


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
        return jsonify({'message': 'No item'})

    return jsonify({'lists': user_lists}), 201


@app.route('/shoppinglists/<list_id>', methods=['DELETE'])
@token_required
def delete_list(current_user, list_id):
    lists = ShoppingList.query.filter_by(id=list_id).first()
    if not lists:
        return jsonify({'message': 'No item'})
    db.session.delete(lists)
    db.session.commit()
    return jsonify({'message': 'list deleted'})


@app.route('/shoppinglists/', methods=['POST'])
@token_required
def create_list(current_user):
    data = request.get_json()
    new_list = ShoppingList(name=data['name'], user_id=data['user_id'])
    db.session.add(new_list)
    db.session.commit()

    return jsonify({'message': 'list added'}), 201


@app.route('/shoppinglists/<list_id>/items', methods=['POST'])
@token_required
def add_list_item(current_user, list_id):
    data = request.get_json()
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

    return jsonify({'list items': list_items}), 201


@app.route('/shoppinglists/<list_id>/items/<item_id>', methods=['PUT'])
@token_required
def edit_list_item(current_user, list_id, item_id):
    data = request.get_json()
    items = Item.query.filter_by(id=item_id).first()
    items.name = data['name']
    db.session.commit()

    return jsonify({'message': 'item edited'}), 201


@app.route('/shoppinglists/<list_id>/items/<item_id>', methods=['DELETE'])
@token_required
def delete_list_item(current_user, list_id, item_id):
    items = Item.query.filter_by(id=item_id).first()
    if not items:
        return jsonify({'message': 'No item'})
    db.session.delete(items)
    db.session.commit()

    return jsonify({'message': 'item deleted'}), 201


@app.route('/auth/logout', methods=['POST'])
def logout():
    pass


@app.route('/auth/reset-password', methods=['POST'])
def reset():
    pass


@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'],  method='sha256')
    new_user = User(name=data['name'], email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created'})


@app.route('/auth/login', methods=['POST'])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response(jsonify('Could not verify', 403, {'WWW-Authenticate': 'Basic realm="Login required!"'}))

    user = User.query.filter_by(email=auth.username).first()

    if not user:
        return make_response(jsonify('Could not verify', 403, {'WWW-Authenticate': 'Basic realm="Login required!"'}))

    if check_password_hash(user.password, auth.password):
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10),
            'iat': datetime.datetime.utcnow(),
            'sub': user.id
        }
        jwt_string = jwt.encode(
            payload,
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        return jwt_string
    return make_response(jsonify('Could not verify', 403, {'WWW-Authenticate': 'Basic realm="Login required!"'}))


if __name__ == '__main__':
    app.run()
