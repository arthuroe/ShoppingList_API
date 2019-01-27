"""
__init__.py
"""

import os

from flask import Flask
from config import app_configuration
from app.errors import bad_request, internal_server_error


app = Flask(__name__)

# app configuration
environment = os.getenv("APP_SETTINGS")
os.sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
app.config.from_object(app_configuration[environment])

app.register_error_handler(400, bad_request)
app.register_error_handler(500, internal_server_error)


from app import views
