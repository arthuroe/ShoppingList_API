import os

from os.path import join, dirname
from dotenv import load_dotenv

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)


class Config:
    """Parent configuration class."""
    DEBUG = False
    TESTING = False
    CSRF_ENABLED = True
    SECRET_KEY = os.getenv('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get("SQLALCHEMY_DATABASE_URI")
    SQLALCHEMY_ECHO = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class DevelopmentConfiguration(Config):
    """Development configuration class."""
    DEBUG = True
    DEVELOPMENT = True


class TestingConfiguration(Config):
    """Testing configuration class."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get("TET_SQLALCHEMY_DATABASE_URI")


class ProductionConfiguration(Config):
    """Production configuration class."""
    DEBUG = False


app_configuration = {
    'production': ProductionConfiguration,
    'development': DevelopmentConfiguration,
    'testing': TestingConfiguration
}
