from datetime import datetime, timedelta
import uuid
from flask import current_app, url_for
from flask_mail import Mail, Message
import os
from app import db
from app.models.user import PasswordResetToken

def send_custom_email(to, subject, body, mail_config):
    """Send email using custom mail configuration"""
    # Create a temporary Flask-Mail instance with custom config
    mail = Mail()
    # Temporarily update app config
    for key, value in mail_config.items():
        current_app.config[key] = value
    mail.init_app(current_app)

    try:
        msg = Message(subject=subject, recipients=[to], body=body)
        mail.send(msg)
        current_app.logger.info(f"Email sent to {to}: {subject}")
        return True
    except Exception as e:
        current_app.logger.error(f"Failed to send email to {to}: {str(e)}")
        return False

def send_verification_email(user, provider='gmail'):
    """Send email verification link to user"""
    if provider == 'gmail':
        mail_config = current_app.config['GMAIL_CONFIG']
    elif provider == 'outlook':
        mail_config = current_app.config['OUTLOOK_CONFIG']
    else:
        current_app.logger.error(f"Invalid email provider: {provider}")
        return False

    # Generate token with expiration
    token = current_app.serializer.dumps(user.email, salt='email-verification')

    # Create verification URL
    verification_url = url_for('auth.verify_email', token=token, _external=True)

    # Create email message
    subject = 'Verify Your Email Address'
    body = f'''Hi {user.username},

Please verify your email address by clicking on the following link:

{verification_url}

This link will expire in 24 hours.

If you did not create an account, please ignore this email.

Regards,
Your Flask Auth App Team
'''

    # Send email using the custom function
    return send_custom_email(user.email, subject, body, mail_config)

def send_password_reset_email(user, provider='gmail', ip_address=None):
    """Send password reset link to user"""
    if provider == 'gmail':
        mail_config = current_app.config['GMAIL_CONFIG']
    elif provider == 'outlook':
        mail_config = current_app.config['OUTLOOK_CONFIG']
    else:
        current_app.logger.error(f"Invalid email provider: {provider}")
        return False
        
    # Generate token
    token = str(uuid.uuid4())

    # Set expiration (24 hours from now)
    expires_at = datetime.utcnow() + timedelta(hours=24)

    # Create or update password reset token
    reset_token = PasswordResetToken.query.filter_by(user_id=user.id, used=False).first()
    if reset_token:
        reset_token.token = token
        reset_token.created_at = datetime.utcnow()
        reset_token.expires_at = expires_at
        reset_token.ip_address = ip_address
    else:
        reset_token = PasswordResetToken(
            user_id=user.id,
            token=token,
            expires_at=expires_at,
            ip_address=ip_address
        )
        db.session.add(reset_token)

    db.session.commit()

    # Create reset URL
    reset_url = url_for('auth.reset_password', token=token, _external=True)

    # Create email message
    subject = 'Reset Your Password'
    body = f'''Hi {user.username},

You requested to reset your password. Please click on the following link to reset it:

{reset_url}

This link is valid for 24 hours.

If you did not request a password reset, please ignore this email and consider changing your password immediately as someone may be attempting to access your account.

Regards,
Your Flask Auth App Team
'''

    # Send email using the custom function
    return send_custom_email(user.email, subject, body, mail_config)