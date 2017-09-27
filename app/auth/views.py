from flask import Flask, jsonify, abort, make_response, request, url_for, Blueprint
from app import app
from app.models import db, User, BlacklistToken
from flask_httpauth import HTTPBasicAuth
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import json
import datetime


auth = Blueprint('auth', __name__)


@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
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
def login():
    #auth = request.authorization
    #if not auth or not auth.username or not auth.password:
        #return make_response(jsonify('Could not verify', 403, {'WWW-Authenticate': 'Basic realm="Login required!"'}))
    data = request.get_json()
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
        responseObject = {
            'status': 'fail',
            'message': 'Try again'
        }
        return make_response(jsonify(responseObject)), 401
