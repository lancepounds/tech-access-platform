
import json # Moved to top
import json
import re
import json
import re
import os
import logging
from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash
from werkzeug.security import generate_password_hash
from app.models import Company
from flask import Blueprint
from .forms import CompanyRegistrationForm
from .schemas import ApproveCompanySchema
from app.extensions import db, limiter
from flask_login import login_required, current_user
from marshmallow import ValidationError

companies_bp = Blueprint('companies', __name__)

# (Admin routes will now use current_user.is_admin and rate limiting via limiter)


@companies_bp.route('/register', methods=['GET'])
def show_register():
    """Show company registration form"""
    form = CompanyRegistrationForm()
    return render_template('company_register.html', form=form)


@companies_bp.route('/register', methods=['POST'])
@limiter.limit("5 per hour;20 per day")
def register_company():
    """Handle company registration"""
    form = CompanyRegistrationForm()
    if form.validate_on_submit():
        company_name = form.company_name.data
        contact_email = form.contact_email.data
        
        # Check if company already exists
        existing_company = Company.query.filter(
            (Company.name == company_name) | (Company.contact_email == contact_email)
        ).first()
        
        if existing_company:
            flash('Company name or email already exists.', 'danger')
            return render_template('company_register.html', form=form) # Re-render with form and error
        
        interests_json = json.dumps(form.interests.data) if form.interests.data else None
        
        new_company = Company(
            name=company_name,
            contact_email=contact_email,
            password=generate_password_hash(form.password.data),
            phone=form.phone.data,
            website=form.website.data,
            address=form.address.data,
            description=form.company_description.data,
            industry=form.industry.data,
            company_size=form.company_size.data,
            products_services=form.products_services.data,
            accessibility_goals=form.accessibility_goals.data,
            interests=interests_json,
            contact_name=form.contact_name.data,
            contact_title=form.contact_title.data,
            accessibility_experience=form.accessibility_experience.data,
            compliance_requirements=form.compliance_requirements.data,
            testing_timeline=form.testing_timeline.data,
            testing_budget=form.testing_budget.data,
            approved=False  # Companies need admin approval
        )
        
        try:
            db.session.add(new_company)
            db.session.commit()
            flash('Company registration submitted successfully! Please wait for admin approval.', 'success')
            return redirect(url_for('auth.login_page'))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error during company registration: {str(e)}")
            flash(f'Registration failed due to an unexpected error. Please try again.', 'danger')
            # Fall through to render form again

    return render_template('company_register.html', form=form)


@companies_bp.route('/pending', methods=['GET'])
@login_required # Added decorator
def list_pending_companies():
    if not current_user.is_admin: # New authorization check
        return jsonify({'error': 'Unauthorized. Admin access required.'}), 403

    pending = Company.query.filter_by(approved=False).all()
    result = [{'id': c.id, 'name': c.name} for c in pending]
    return jsonify(result), 200


@companies_bp.route('/approve', methods=['POST'])
@login_required # Added decorator
def approve_company():
    if not current_user.is_admin: # New authorization check
        return jsonify({'error': 'Unauthorized. Admin access required.'}), 403

    request_data = request.get_json()
    if request_data is None: # Explicitly check for None
        return jsonify({"error": "No input data provided or malformed JSON"}), 400

    try:
        data = ApproveCompanySchema().load(request_data) # Pass request_data directly
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400

    company_name = data['name'] # Use validated data

    company = Company.query.filter_by(name=company_name).first()
    if not company:
        return jsonify({'error': 'Company not found'}), 404

    if company.approved:
        return jsonify({'message': 'Company already approved'}), 200

    company.approved = True
    try:
        db.session.commit()
        return jsonify({'message': f'Company {company_name} approved'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to approve company: {str(e)}'}), 500
