from flask import jsonify


def bad_request(e):
    return jsonify({'Error': 'Bad Request'}), 400


def internal_server_error(e):
    return jsonify({'Error': 'Internal Server Error'}), 500
