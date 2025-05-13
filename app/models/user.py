from flask_login import UserMixin
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash
import secrets
from app import db

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)  # Increased length for stronger hashing
    role = db.Column(db.String(20), default='user')  # 'user', 'admin', 'moderator'
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    login_attempts = db.Column(db.Integer, default=0)  # Track failed login attempts
    account_locked_until = db.Column(db.DateTime)  # For temporary account lockouts
    
    # Session tracking for better security
    active_sessions = db.relationship('UserSession', backref='user', lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<User {self.username}>'
    
    def check_password(self, password):
        """Verify password and handle login attempt counting"""
        is_correct = check_password_hash(self.password_hash, password)
        
        if is_correct:
            # Reset login attempts on successful login
            self.login_attempts = 0
        else:
            # Increment login attempts on failed login
            self.login_attempts += 1
            
            # Lock account after 5 failed attempts
            if self.login_attempts >= 5:
                self.account_locked_until = datetime.utcnow() + timedelta(minutes=15)
                # Logging is handled in the service layer
                
        db.session.commit()
        return is_correct
    
    def is_account_locked(self):
        """Check if account is temporarily locked"""
        if self.account_locked_until and self.account_locked_until > datetime.utcnow():
            return True
        return False
    
    def create_session(self, ip_address, user_agent):
        """Create a new session for this user"""
        # Create a secure session token
        token = secrets.token_hex(32)
        
        # Store session in database
        session = UserSession(
            user_id=self.id,
            session_token=token,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=datetime.utcnow() + timedelta(days=30)
        )
        
        db.session.add(session)
        db.session.commit()
        return token
    
    def invalidate_all_sessions(self):
        """Invalidate all sessions for this user"""
        self.active_sessions.delete()
        db.session.commit()

class UserSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_token = db.Column(db.String(64), unique=True, nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)  # Support for IPv6
    user_agent = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    def is_valid(self):
        """Check if session is still valid"""
        return self.is_active and self.expires_at > datetime.utcnow()

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    ip_address = db.Column(db.String(45))  # Track IP address for security

class LoginAttempt(db.Model):
    """Track login attempts for security monitoring"""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120))  # Store even for non-existent users
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(255))
    success = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)