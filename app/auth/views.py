"""
Authentication Blueprint
"""

import datetime
import re
from functools import wraps
from flask import jsonify, make_response, request, Blueprint
from app import app
from app.models import db, User
from werkzeug.security import check_password_hash
import jwt

auth = Blueprint('auth', __name__)


def require_fields(*fields, **kwfields):
    """
    This function validates user input
    """
    def decorate(func):
        """
        This function validates user input
        """
        @wraps(func)
        def wrap(*args, **kwargs):
            """
            This function validates user input
            """
            for field in fields:
                if not request.get_json(field, None):
                    return jsonify({
                        "error_msg": "Please fill all fields"
                    })
            for key, value in kwfields.items():
                if not re.match(r'{}'.format(value), request.get_json(key, None)):
                    return jsonify({
                        "error_msg": "Invalid {}".format(key)
                    })
            return func(*args, **kwargs)
        return wrap
    return decorate


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


@app.route('/api/v1/auth/register', methods=['POST'])
@require_fields('name', 'email', 'password')
def register():
    """
    This route enables a user to register with the API
    """
    data = request.get_json()
    if not data['email'] or not data['password'] or not data['name']:
        return make_response(jsonify({"message": "All fields are required"})), 403
    user = User.query.filter_by(email=data['email'],).first()
    if not user:
        new_user = User(
            name=data['name'], email=data['email'], password=data['password'])
        db.session.add(new_user)
        db.session.commit()
        response = {
            'status': 'success',
            'message': 'Successfully registered.'
        }
        return make_response(jsonify(response)), 201
    else:
        response = {
            'status': 'fail',
            'message': 'User already exists. Please Log in.',
        }
        return make_response(jsonify(response)), 401


@app.route('/api/v1/auth/login', methods=['POST'])
@require_fields('email', 'password')
def login():
    """
    This route enables a user to login into the API
    """
    data = request.get_json()

    if not data['email'] or not data['password']:
        return make_response(jsonify({"message": "All fields are required"})), 403
    user = User.query.filter_by(email=data['email']).first()
    if not user:
        response = {
            'status': 'fail',
            'message': 'User does not exist.'
        }
        return make_response(jsonify(response)), 401

    if check_password_hash(user.password, data['password']):
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=5000),
            'iat': datetime.datetime.utcnow(),
            'sub': user.id
        }
        jwt_string = jwt.encode(
            payload,
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        response = {
            'status': 'success',
            'message': 'You logged in successfully.',
            'access_token': jwt_string.decode(),
            'welcome': 'Hi ' + user.name
        }
        return make_response(jsonify(response)), 200
    else:
        response = {
            'message': 'Failed to login'
        }
        return make_response(jsonify(response)), 401
