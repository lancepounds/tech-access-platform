
from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash
from werkzeug.security import generate_password_hash
from app.models import Company
from app.extensions import db
import json

companies_bp = Blueprint('companies', __name__)

# Simple admin token (in production, use real authentication)
ADMIN_TOKEN = "my-secret-admin-token"


@companies_bp.route('/register', methods=['GET'])
def show_register():
    """Show company registration form"""
    return render_template('company_register.html')


@companies_bp.route('/register', methods=['POST'])
def register_company():
    """Handle company registration"""
    try:
        # Get form data
        company_name = request.form.get('company_name')
        contact_email = request.form.get('contact_email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not company_name or not contact_email or not password:
            flash('Company name, email, and password are required.', 'danger')
            return redirect(url_for('companies.show_register'))
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('companies.show_register'))
        
        # Check if company already exists
        existing_company = Company.query.filter(
            (Company.name == company_name) | (Company.contact_email == contact_email)
        ).first()
        
        if existing_company:
            flash('Company name or email already exists.', 'danger')
            return redirect(url_for('companies.show_register'))
        
        # Get checkbox interests
        interests = request.form.getlist('interests')
        interests_json = json.dumps(interests) if interests else None
        
        # Create new company
        new_company = Company(
            name=company_name,
            contact_email=contact_email,
            password=generate_password_hash(password),
            phone=request.form.get('phone'),
            website=request.form.get('website'),
            address=request.form.get('address'),
            description=request.form.get('company_description'),
            industry=request.form.get('industry'),
            company_size=request.form.get('company_size'),
            products_services=request.form.get('products_services'),
            accessibility_goals=request.form.get('accessibility_goals'),
            interests=interests_json,
            # New fields
            contact_name=request.form.get('contact_name'),
            contact_title=request.form.get('contact_title'),
            accessibility_experience=request.form.get('accessibility_experience'),
            compliance_requirements=request.form.get('compliance_requirements'),
            testing_timeline=request.form.get('testing_timeline'),
            testing_budget=request.form.get('testing_budget'),
            approved=False  # Companies need admin approval
        )
        
        db.session.add(new_company)
        db.session.commit()
        
        flash('Company registration submitted successfully! Please wait for admin approval.', 'success')
        return redirect(url_for('auth.login_page'))
        
    except Exception as e:
        db.session.rollback()
        flash(f'Registration failed: {str(e)}', 'danger')
        return redirect(url_for('companies.show_register'))


@companies_bp.route('/pending', methods=['GET'])
def list_pending_companies():
    token = request.headers.get('Authorization')
    if token != f"Bearer {ADMIN_TOKEN}":
        return jsonify({'error': 'Unauthorized'}), 403

    pending = Company.query.filter_by(approved=False).all()
    result = [{'id': c.id, 'name': c.name} for c in pending]
    return jsonify(result), 200


@companies_bp.route('/approve', methods=['POST'])
def approve_company():
    token = request.headers.get('Authorization')
    if token != f"Bearer {ADMIN_TOKEN}":
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    company_name = data.get('name')

    if not company_name:
        return jsonify({'error': 'Missing company name'}), 400

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
