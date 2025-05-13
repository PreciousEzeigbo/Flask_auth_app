import re
from flask import request

def validate_password_strength(password):
    """
    Validate password strength:
    - At least 8 characters
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one digit
    - Contains at least one special character
    
    Returns:
        tuple: (is_valid: bool, message: str)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
        
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
        
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
        
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
        
    return True, "Password strength acceptable"

def validate_email(email):
    """
    Validate email format
    Basic email validation using regex
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(pattern, email):
        return True
    return False

def sanitize_username(username):
    """
    Sanitize username - only allow alphanumeric chars and some symbols
    """
    # Remove potentially dangerous characters
    pattern = r'[^a-zA-Z0-9_.-]'
    return re.sub(pattern, '', username)

def get_client_ip():
    """Get client IP address from request"""
    if request.headers.getlist("X-Forwarded-For"):
        # For proxy servers
        return request.headers.getlist("X-Forwarded-For")[0].split(',')[0]
    return request.remote_addr