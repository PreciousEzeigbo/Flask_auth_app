from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from flask_login import current_user, login_user
from ..models.user import User, LoginAttempt
from ..models.user import PasswordResetToken
from .. import db
from ..services.rate_limiter import RateLimiter
from ..services.security import validate_password_strength, validate_email, sanitize_username
from ..services.email import send_verification_email, send_password_reset_email
from ..utils.decorators import login_required
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash
import secrets

# Only define the blueprint once
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# Initialize the rate limiter
rate_limiter = RateLimiter()

def get_serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0].split(',')[0]
    return request.remote_addr

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        remember_me = 'remember_me' in request.form
        ip_address = get_client_ip()
        user_agent = request.headers.get('User-Agent', 'Unknown')

        # Global IP-based rate limiting
        if rate_limiter.is_limited(key=f"login:{ip_address}", max_attempts=5, window_seconds=300):
            current_app.logger.warning(f"Rate limit hit for login from IP: {ip_address}")
            flash('Too many login attempts. Please try again later.', 'danger')
            return redirect(url_for('auth.login'))

        # Record login attempt before validation
        login_attempt = LoginAttempt(
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False
        )
        db.session.add(login_attempt)

        user = User.query.filter_by(email=email).first()

        if not user:
            db.session.commit()
            # Use a constant-time response to prevent timing attacks
            flash('Invalid username or password', 'danger')
            return redirect(url_for('auth.login'))

        if user.is_account_locked():
            db.session.commit()
            flash('This account has been temporarily locked due to multiple failed login attempts. Please try again later.', 'danger')
            return redirect(url_for('auth.login'))

        # Use constant-time comparison for password check
        if user.check_password(password):
            login_attempt.success = True
            db.session.commit()
            
            if not user.is_verified:
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('auth.login'))
                
            # Store user ID in session
            session.clear()  # Clear any existing session data first
            session['user_id'] = user.id
            login_user(user)
            session['username'] = user.username
            # Create a new session token
            session_token = user.create_session(ip_address, user_agent)
            session['session_token'] = session_token
            
            # Handle remember me functionality
            if remember_me:
                session.permanent = True
                current_app.permanent_session_lifetime = timedelta(days=30)
            else:
                session.permanent = False
                
            # Update last login timestamp
            user.last_login = datetime.utcnow()
            user.login_attempts = 0  # Reset failed login counter on successful login
            db.session.commit()
            
            # Reset rate limiter on successful login
            rate_limiter.reset(key=f"login:{ip_address}")
            current_app.logger.info(f"User logged in: {user.username} (IP: {ip_address})")
            flash('Login successful!', 'success')
            
            # Handle redirect
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
                
            # Role-based redirects
            if user.role == 'admin':
                return redirect(url_for('admin.dashboard'))
            elif user.role == 'moderator':
                return redirect(url_for('main.moderator_dashboard'))
            else:
                return redirect(url_for('main.dashboard'))
        else:
            # Increment failed login attempts
            if user:
                user.login_attempts = (user.login_attempts or 0) + 1
                
                # Lock account after 5 failed attempts
                if user.login_attempts >= 5:
                    user.account_locked_until = datetime.utcnow() + timedelta(minutes=30)
                    current_app.logger.warning(f"Account locked for user: {user.username} after multiple failed attempts")
            
            db.session.commit()
            flash('Invalid username or password', 'danger')
            return redirect(url_for('auth.login'))

    return render_template('login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate email provider - whitelist approach for security
        allowed_providers = ['gmail', 'outlook', 'yahoo', 'protonmail']
        email_provider = request.form.get('email_provider', '')
        if email_provider not in allowed_providers:
            email_provider = 'gmail'  # Default to a safe value
        
        # IP for security tracking
        ip_address = get_client_ip()
        
        # Check if registration attempts from this IP are rate limited
        if rate_limiter.is_limited(key=f"register:{ip_address}", max_attempts=5, window_seconds=300):
            current_app.logger.warning(f"Rate limit hit for registration from IP: {ip_address}")
            flash('Too many registration attempts. Please try again later.', 'danger')
            return redirect(url_for('auth.register'))
        
        # Validate username
        if not username or len(username) < 3 or len(username) > 30:
            flash('Username must be between 3 and 30 characters', 'danger')
            return redirect(url_for('auth.register'))
            
        # Clean username of potentially dangerous characters
        username = sanitize_username(username)
        
        # Validate email
        if not email or not validate_email(email):
            flash('Please enter a valid email address', 'danger')
            return redirect(url_for('auth.register'))

        # Check password strength
        is_strong, message = validate_password_strength(password)
        if not is_strong:
            flash(message, 'danger')
            return redirect(url_for('auth.register'))

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('auth.register'))

        # Check if username already exists - use constant time operation for security
        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        
        if existing_user or existing_email:
            # Don't reveal whether it was the username or email that existed
            flash('Registration failed. Please try again with different credentials.', 'danger')
            return redirect(url_for('auth.register'))

        try:
            # Create new user with stronger password hash
            new_user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
            )

            # Add user to database
            db.session.add(new_user)
            db.session.commit()

            # Send verification email
            if send_verification_email(new_user, email_provider):
                flash('Registration successful! Please check your email to verify your account.', 'success')
                current_app.logger.info(f"New user registered: {username} (IP: {ip_address})")
            else:
                flash('Registration successful, but there was a problem sending the verification email. Please contact support.', 'warning')
                current_app.logger.error(f"Failed to send verification email to new user: {username}")
                
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error during user registration: {str(e)}")
            flash('An error occurred during registration. Please try again later.', 'danger')
            return redirect(url_for('auth.register'))

    return render_template('register.html')

@auth_bp.route('/verify-email/<token>')
def verify_email(token):
    try:
        # Try to decode token (max age 1 day/24 hours)
        serializer = get_serializer()
        email = serializer.loads(token, salt='email-verification', max_age=86400)

        # Find user by email
        user = User.query.filter_by(email=email).first()

        if user:
            # Update user verification status if not already verified
            if not user.is_verified:
                user.is_verified = True
                user.email_verified_at = datetime.utcnow()  # Track when verification happened
                db.session.commit()
                flash('Your email has been verified! You can now log in.', 'success')
                current_app.logger.info(f"Email verified for user: {user.username}")
            else:
                flash('Your email is already verified.', 'info')
        else:
            flash('User not found.', 'danger')
            current_app.logger.warning(f"Email verification attempt for non-existent user: {email}")

    except SignatureExpired:
        flash('The verification link has expired. Please request a new one.', 'warning')
    except BadSignature:
        flash('Invalid verification link.', 'danger')
        current_app.logger.warning(f"Invalid email verification token used: {token}")
    except Exception as e:
        flash('An error occurred during verification.', 'danger')
        current_app.logger.error(f"Error during email verification: {str(e)}")

    return redirect(url_for('auth.login'))

@auth_bp.route('/resend-verification')
@login_required
def resend_verification():
    user = User.query.get(session['user_id'])

    if user and not user.is_verified:
        # Check for rate limiting
        if rate_limiter.is_limited(key=f"verification:{user.id}", max_attempts=3, window_seconds=3600):
            flash('Too many verification email requests. Please try again later.', 'warning')
            return redirect(url_for('main.dashboard'))
            
        # Auto-select email provider based on email domain or use default
        email_domain = user.email.split('@')[1].lower() if '@' in user.email else ''
        email_provider = 'gmail'  # Default
        
        # Basic provider detection based on common domains
        if 'outlook' in email_domain or 'hotmail' in email_domain:
            email_provider = 'outlook'
        elif 'yahoo' in email_domain:
            email_provider = 'yahoo'
        elif 'protonmail' in email_domain:
            email_provider = 'protonmail'
            
        if send_verification_email(user, email_provider):
            flash('Verification email has been resent. Please check your inbox.', 'success')
        else:
            flash('Failed to send verification email. Please try again later.', 'danger')
    else:
        flash('Your email is already verified or user not found.', 'info')

    return redirect(url_for('main.dashboard'))

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        ip_address = get_client_ip()
        
        # Check if password reset attempts from this IP are rate limited
        if rate_limiter.is_limited(key=f"password_reset:{ip_address}", max_attempts=3, window_seconds=3600):
            current_app.logger.warning(f"Rate limit hit for password reset from IP: {ip_address}")
            flash('Too many password reset attempts. Please try again later.', 'warning')
            return redirect(url_for('auth.forgot_password'))
            
        if email and validate_email(email):
            user = User.query.filter_by(email=email).first()

            if user:
                # Invalidate any existing unused tokens for this user
                existing_tokens = PasswordResetToken.query.filter_by(
                    user_id=user.id, 
                    used=False
                ).all()
                
                for token in existing_tokens:
                    token.used = True
                
                # Create new token with cryptographically secure value
                token_value = secrets.token_urlsafe(32)
                new_token = PasswordResetToken(
                    user_id=user.id,
                    token=token_value,
                    ip_address=ip_address,
                    expires_at=datetime.utcnow() + timedelta(hours=1)  # 1 hour expiry
                )
                db.session.add(new_token)
                db.session.commit()
                
                current_app.logger.info(f"Password reset requested for {email} from IP: {ip_address}")
                # Send password reset email with token
                send_password_reset_email(user, token_value, ip_address=ip_address)
            else:
                current_app.logger.info(f"Password reset attempted for non-existent email: {email} from IP: {ip_address}")
                
            # For security reasons, show the same message whether the email exists or not
            flash('If an account with that email exists, a password reset link has been sent.', 'info')
        else:
            flash('Please enter a valid email address', 'warning')
            
        return redirect(url_for('auth.login'))

    return render_template('forgot_password.html')

@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Find reset token in database
    reset_token = PasswordResetToken.query.filter_by(token=token, used=False).first()
    ip_address = get_client_ip()

    # Check if token exists and is valid
    if not reset_token or reset_token.expires_at < datetime.utcnow():
        current_app.logger.warning(f"Invalid or expired password reset token used from IP: {ip_address}")
        flash('Invalid or expired password reset link.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Check password strength
        is_strong, message = validate_password_strength(password)
        if not is_strong:
            flash(message, 'danger')
            return redirect(url_for('auth.reset_password', token=token))

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('auth.reset_password', token=token))

        try:
            # Get user
            user = User.query.get(reset_token.user_id)
            
            # Check if new password is the same as current password 
            if user.check_password(password):
                flash('New password cannot be the same as your current password', 'danger')
                return redirect(url_for('auth.reset_password', token=token))
            
            # Update user's password with stronger hash
            user.password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
            user.password_changed_at = datetime.utcnow()  # Track when password was changed
            
            # Reset login attempts
            user.login_attempts = 0
            user.account_locked_until = None
            
            # Mark token as used
            reset_token.used = True
            reset_token.used_at = datetime.utcnow()
            
            # Invalidate all existing sessions for security
            user.invalidate_all_sessions()
            
            db.session.commit()
            
            current_app.logger.info(f"Password reset successful for user: {user.username}")
            flash('Your password has been reset successfully. You can now log in with your new password.', 'success')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error during password reset: {str(e)}")
            flash('An error occurred during password reset. Please try again.', 'danger')
            return redirect(url_for('auth.reset_password', token=token))

    return render_template('reset_password.html', token=token)

@auth_bp.route('/logout')
@login_required
def logout():
    user_id = session.get('user_id')
    session_token = session.get('session_token')
    
    if user_id and session_token:
        user = User.query.get(user_id)
        if user:
            # Invalidate current session in database
            user.invalidate_session(session_token)
    
    # Clear the session data
    session.clear()
    
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        user = User.query.get(session['user_id'])
        
        if not user.check_password(current_password):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('auth.change_password'))
            
        if current_password == new_password:
            flash('New password must be different from your current password', 'danger')
            return redirect(url_for('auth.change_password'))
            
        # Check password strength
        is_strong, message = validate_password_strength(new_password)
        if not is_strong:
            flash(message, 'danger')
            return redirect(url_for('auth.change_password'))
            
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('auth.change_password'))
            
        try:
            # Update password
            user.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=16)
            user.password_changed_at = datetime.utcnow()
            
            # For security, invalidate all other sessions when password is changed
            current_session = session.get('session_token')
            user.invalidate_all_sessions_except(current_session)
            
            db.session.commit()
            
            flash('Your password has been changed successfully.', 'success')
            return redirect(url_for('main.dashboard'))
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error during password change: {str(e)}")
            flash('An error occurred while changing your password. Please try again.', 'danger')
            
    return render_template('change_password.html')

@auth_bp.route('/account/settings')
@login_required
def account_settings():
    return render_template('account_settings.html', current_user=current_user)
