from flask import Flask, jsonify, abort, make_response, request, url_for, Blueprint
from app import app
from app.models import db, User, BlacklistToken
from flask_httpauth import HTTPBasicAuth
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import re
import jwt
import json
import datetime

auth = Blueprint('auth', __name__)


def require_fields(*fields):
    def decorate(func):
        @wraps(func)
        def wrap(*args, **kwargs):
            for field in fields:
                if not request.get_json(field, None):
                    return jsonify({
                        "error_msg": "Please fill all fields"
                    })

            return func(*args, **kwargs)

        return wrap
    return decorate


@app.route('/auth/register', methods=['POST'])
@require_fields('name', 'email', 'password')
def register():
    data = request.get_json()
    if not data['email'] or not data['password'] or not data['name']:
        return make_response(jsonify({"message": "All fields are required"})), 403
    user = User.query.filter_by(email=data['email'],).first()
    if not user:
        new_user = User(name=data['name'], email=data['email'], password=data['password'])
        db.session.add(new_user)
        db.session.commit()
        responseObject = {
            'status': 'success',
            'message': 'Successfully registered.'
        }
        return make_response(jsonify(responseObject)), 201
    else:
        responseObject = {
            'status': 'fail',
            'message': 'User already exists. Please Log in.',
        }
        return make_response(jsonify(responseObject)), 202


@app.route('/auth/login', methods=['POST'])
@require_fields('email', 'password')
def login():

    data = request.get_json()

    if not data['email'] or not data['password']:
        return make_response(jsonify({"message": "All fields are required"})), 403
    user = User.query.filter_by(email=data['email']).first()
    if not user:
        responseObject = {
            'status': 'fail',
            'message': 'User does not exist.'
        }
        return make_response(jsonify(responseObject)), 401

    if check_password_hash(user.password, data['password']):
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=20),
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
            'access_token': jwt_string.decode()
        }

        return make_response(jsonify(response)), 200

    else:
        response = {
            'message': 'Failed to login'
        }
        return make_response(jsonify(response)), 401
