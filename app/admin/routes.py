from flask import render_template, abort, flash, redirect, url_for
from flask_login import login_required, current_user
from . import admin_bp
from app.models import Company, User # Added User model
from app.extensions import db
from .forms import ApproveCompanyForm, DenyCompanyForm, ToggleAdminForm # Added ToggleAdminForm

@admin_bp.route('/')
@login_required
def dashboard():
    if not current_user.is_admin:
        abort(403)
    return render_template('admin/admin_dashboard.html', title="Admin Dashboard")

@admin_bp.route('/companies/pending')
@login_required
def pending_companies():
    if not current_user.is_admin:
        abort(403)
    pending_list = Company.query.filter_by(approved=False).order_by(Company.created_at.desc()).all()
    approve_form = ApproveCompanyForm()
    # deny_form = DenyCompanyForm() # If adding deny
    return render_template('admin/pending_companies.html',
                           pending_list=pending_list,
                           approve_form=approve_form,
                           # deny_form=deny_form,
                           title="Pending Company Approvals")

@admin_bp.route('/companies/<int:company_id>/approve', methods=['POST'])
@login_required
def approve_company_admin(company_id):
    if not current_user.is_admin:
        abort(403)
    form = ApproveCompanyForm() # For CSRF validation
    if form.validate_on_submit(): # Validates CSRF
        company = Company.query.get_or_404(company_id)
        company.approved = True
        db.session.commit()
        flash(f"Company '{company.name}' approved successfully.", "success")
    else:
        # This else block will catch CSRF errors if they occur or other form validation errors.
        flash("Invalid request or CSRF token missing/invalid.", "danger")
    return redirect(url_for('admin.pending_companies'))

@admin_bp.route('/users')
@login_required
def list_users():
    if not current_user.is_admin:
        abort(403)
    users = User.query.order_by(User.email).all()
    toggle_admin_form = ToggleAdminForm() # For CSRF token for all toggle buttons
    return render_template('admin/list_users.html',
                           users=users,
                           toggle_admin_form=toggle_admin_form,
                           title="User Management")

@admin_bp.route('/users/<string:user_id>/toggle-admin', methods=['POST'])
@login_required
def toggle_admin_status(user_id):
    if not current_user.is_admin:
        abort(403)

    form = ToggleAdminForm() # For CSRF validation
    if form.validate_on_submit():
        user_to_modify = User.query.get(user_id) # User.id is a string UUID
        if not user_to_modify:
            flash("User not found.", "danger")
            return redirect(url_for('admin.list_users'))

        # Basic safeguard: Prevent admin from revoking their own status via this simple toggle.
        if current_user.id == user_to_modify.id:
            flash("Admins cannot change their own admin status via this button.", "warning")
            return redirect(url_for('admin.list_users'))

        user_to_modify.is_admin = not user_to_modify.is_admin
        db.session.commit()
        flash(f"Admin status for {user_to_modify.email} has been {'granted' if user_to_modify.is_admin else 'revoked'}.", "success")
    else:
        # This primarily catches CSRF errors if any, as the form has no other validators.
        flash("Invalid request or CSRF token missing.", "danger")
    return redirect(url_for('admin.list_users'))
