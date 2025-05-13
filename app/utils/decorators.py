from functools import wraps
from flask import session, redirect, url_for, flash, request
from app.models.user import User

def login_required(f):
    """Decorator to require login for a route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role for a route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('auth.login', next=request.url))
            
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            flash('You do not have permission to access this page', 'danger')
            return redirect(url_for('main.dashboard'))
            
        return f(*args, **kwargs)
    return decorated_function

def moderator_required(f):
    """Decorator to require moderator or admin role for a route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('auth.login', next=request.url))
            
        user = User.query.get(session['user_id'])
        if not user or (user.role != 'moderator' and user.role != 'admin'):
            flash('You do not have permission to access this page', 'danger')
            return redirect(url_for('main.dashboard'))
            
        return f(*args, **kwargs)
    return decorated_function