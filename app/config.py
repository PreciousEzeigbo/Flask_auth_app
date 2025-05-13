import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Base configuration class"""
    SECRET_KEY = os.environ['SECRET_KEY']
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Email config
    MAIL_SERVER = 'smtp.example.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ['MAIL_USERNAME']
    MAIL_PASSWORD = os.environ['MAIL_PASSWORD']
    MAIL_DEFAULT_SENDER = os.environ['MAIL_DEFAULT_SENDER']

    GMAIL_CONFIG = {
        'MAIL_SERVER': 'smtp.gmail.com',
        'MAIL_PORT': 587,
        'MAIL_USE_TLS': True,
        'MAIL_USERNAME': os.environ['GMAIL_USERNAME'],
        'MAIL_PASSWORD': os.environ['GMAIL_APP_PASSWORD'],
        'MAIL_DEFAULT_SENDER': os.environ['GMAIL_SENDER']
    }

    OUTLOOK_CONFIG = {
        'MAIL_SERVER': 'smtp.office365.com',
        'MAIL_PORT': 587,
        'MAIL_USE_TLS': True,
        'MAIL_USERNAME': os.environ['OUTLOOK_USERNAME'],
        'MAIL_PASSWORD': os.environ['OUTLOOK_PASSWORD'],
        'MAIL_DEFAULT_SENDER': os.environ['OUTLOOK_SENDER']
    }

    PERMANENT_SESSION_LIFETIME = timedelta(days=30)
    PASSWORD_RESET_TOKEN_EXPIRES = 86400
    EMAIL_VERIFICATION_TOKEN_EXPIRES = 86400
    DEFAULT_RATE_LIMIT_MAX_ATTEMPTS = 5
    DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 300
    MAX_LOGIN_ATTEMPTS = 5
    ACCOUNT_LOCKOUT_MINUTES = 15

class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False

class ProductionConfig(Config):
    DEBUG = False
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True
