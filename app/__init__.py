"""
__init__.py
"""

from flask import Flask
from app.errors import bad_request, internal_server_error


app = Flask(__name__)

app.register_error_handler(400, bad_request)
app.register_error_handler(500, internal_server_error)

from app import views
