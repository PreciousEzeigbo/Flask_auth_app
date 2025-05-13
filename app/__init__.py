from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer
import os
import secrets
import logging
from logging.handlers import RotatingFileHandler
from flask_login import LoginManager

login_manager = LoginManager()
login_manager.login_view = 'auth.login'  # or your login route name


# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
mail = Mail()

def create_app(config_object='app.config.Config'):
    """Application factory function"""
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config_object)
    
    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    login_manager.init_app(app)  # Initialize login_manager with app
    
    from app.models.user import User 
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    # Set up logging
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/flask_auth.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Flask Authentication startup')
    
    # Create URL safe time serializer for tokens
    app.serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    
    # Register blueprints
    from app.routes.main import main as main_blueprint
    app.register_blueprint(main_blueprint)
    
    from app.routes.auth import auth_bp as auth_blueprint
    app.register_blueprint(auth_blueprint)
    
    from app.routes.admin import admin_bp as admin_blueprint
    app.register_blueprint(admin_blueprint)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register context processors
    register_context_processors(app)
    
    # Register middleware
    register_middleware(app)
    
    # Create DB tables (for initial setup)
    with app.app_context():
        db.create_all()
    
    return app

def register_error_handlers(app):
    """Register error handlers"""
    from flask import render_template
    
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        app.logger.error(f"Internal server error: {str(e)}")
        return render_template('errors/500.html'), 500

def register_context_processors(app):
    """Register context processors"""
    @app.context_processor
    def utility_processor():
        def is_safe_redirect_url(url):
            """Check if URL is safe for redirects"""
            if not url or url.startswith('//') or ':' in url:
                return False
            return True
            
        return dict(is_safe_redirect_url=is_safe_redirect_url)

def register_middleware(app):
    """Register middleware functions"""
    from flask import session, request, redirect, url_for, flash
    from app.models.user import UserSession
    
    @app.before_request
    def check_session_validity():
        if 'user_id' in session and request.endpoint != 'static':
            user_id = session.get('user_id')
            session_token = session.get('session_token')
            
            if user_id and session_token:
                # Check if this session is still valid in the database
                user_session = UserSession.query.filter_by(
                    user_id=user_id,
                    session_token=session_token,
                    is_active=True
                ).first()
                
                if not user_session or not user_session.is_valid():
                    # Session is invalid or expired, force logout
                    session.clear()
                    flash('Your session has expired. Please log in again.', 'warning')
                    return redirect(url_for('auth.login'))