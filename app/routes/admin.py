from flask import Blueprint, render_template
from ..utils.decorators import admin_required

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    return render_template('admin_dashboard.html')

@admin_bp.route('/manage-users')
def manage_users():
    return render_template('manage_users.html')

@admin_bp.route('/view-logs')
def view_logs():
    return render_template('view_logs.html')

@admin_bp.route('/site-settings', methods=['GET', 'POST'])
def site_settings():
    # handle form logic here if POST
    return render_template('site_settings.html')
