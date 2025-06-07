from flask import Blueprint, request, jsonify, render_template, session, flash, redirect, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from app.models import User, Company
from .forms import LoginForm
from flask_login import login_user, logout_user
from flask_jwt_extended import create_access_token # Import create_access_token
from app.auth.decorators import decode_token
from app.extensions import db
from sqlalchemy.exc import IntegrityError
import jwt # Re-enable for web login session token
import datetime
import os
import logging

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

JWT_SECRET = os.environ.get('JWT_SECRET')
if JWT_SECRET is None:
    JWT_SECRET = 'fallback-jwt-secret'
    logging.warning("SECURITY WARNING: Using default JWT_SECRET. This should be changed for production environments.")


@auth_bp.route('/signup', methods=['GET'])
def signup_page():
    return render_template('signup.html')

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing email or password'}), 400

    # Check if user already exists
    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        return jsonify({'error': 'Email already registered'}), 400

    # Create new user
    hashed_password = generate_password_hash(data['password'])
    role = data.get('role', 'user')  # Default to 'user' if no role specified

    # Map 'member' to 'user' and 'company' to 'company'
    if role == 'member':
        role = 'user'

    new_user = User(
        email=data['email'],
        password=hashed_password,
        role=role
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except IntegrityError as e:
        db.session.rollback()
        logging.error(f"IntegrityError during user registration: {str(e)}")
        return jsonify({'error': 'Database integrity error during registration.'}), 500
    except Exception as e:
        db.session.rollback()
        logging.error(f"Exception during user registration: {str(e)}")
        return jsonify({'error': f'Failed to create user: {str(e)}'}), 500


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            # Generate JWT token for user
            token = jwt.encode({
                'email': user.email,
                'role': user.role,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, JWT_SECRET, algorithm='HS256')

            # Store login info in session and Flask-Login
            login_user(user)
            session['token'] = token
            session['email'] = user.email
            session['role'] = user.role

            flash('Logged in successfully', 'success')
            return redirect(url_for('main.show_events'))

        company = Company.query.filter_by(contact_email=email).first()
        if company and check_password_hash(company.password, password):
            if not company.approved:
                flash('Your company account is pending approval. Please wait for admin approval.', 'warning')
                return render_template('login.html', form=form)

            # Generate JWT token for company
            token = jwt.encode({
                'email': company.contact_email,
                'role': company.role,
                'company_id': company.id,
                'approved': company.approved,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, JWT_SECRET, algorithm='HS256')

            # Store login info in session
            session['token'] = token
            session['email'] = company.contact_email
            session['role'] = company.role
            session['company_id'] = company.id

            flash('Logged in successfully', 'success')
            return redirect(url_for('dashboard.company_dashboard'))

        flash('Invalid credentials', 'danger')

    return render_template('login.html', form=form)


    # Use existing JWT login logic - THIS PART IS BEING REPLACED AND RE-INDENTED ABOVE
    # user = User.query.filter_by(email=email).first()

    # if user and check_password_hash(user.password, password):
        # Generate JWT token for user
        # token = jwt.encode({
        #     'email': user.email,
        #     'role': user.role,
        #     'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        # }, JWT_SECRET, algorithm='HS256')

        # Store login info in session and Flask-Login
        # login_user(user)
        # session['token'] = token
        # session['email'] = user.email
        # session['role'] = user.role

        # flash('Logged in successfully', 'success')
        # return redirect(url_for('main.show_events'))

    # Check if it's a company login
    # company = Company.query.filter_by(contact_email=email).first()
    # if company and check_password_hash(company.password, password):
    #     if not company.approved:
    #         flash('Your company account is pending approval. Please wait for admin approval.', 'warning')
    #         return render_template('login.html', form=form) # Pass form here too

        # Generate JWT token for company
        # token = jwt.encode({
        #     'email': company.contact_email,
        #     'role': company.role,
        #     'company_id': company.id,
        #     'approved': company.approved,
        #     'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        # }, JWT_SECRET, algorithm='HS256')

        # Store login info in session
        # session['token'] = token
        # session['email'] = company.contact_email
        # session['role'] = company.role
        # session['company_id'] = company.id

        # flash('Logged in successfully', 'success')
        # return redirect(url_for('dashboard.company_dashboard'))

    # flash('Invalid credentials', 'danger')
    # return render_template('login.html', form=form) # And here


@auth_bp.route('/logout', methods=['POST'])
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('main.index'))


@auth_bp.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing credentials'}), 400

    user = User.query.filter_by(email=data['email']).first()
    company = Company.query.filter_by(contact_email=data['email']).first()

    if user and check_password_hash(user.password, data['password']):
        # Identity can be user.id or user.email, depending on setup.
        # flask-jwt-extended uses 'sub' claim for identity.
        # Additional claims are for 'role', 'email' etc.
        additional_claims = {"role": user.role, "email": user.email}
        token = create_access_token(identity=str(user.id), additional_claims=additional_claims) # Use 'token' as key
        return jsonify(token=token, role='user'), 200

    if company and check_password_hash(company.password, data['password']):
        if not company.approved:
             return jsonify({"error": "Company account not approved"}), 403

        # For companies, ensure company_id is part of the claims
        additional_claims = {
            "role": company.role,
            "email": company.contact_email,
            "company_id": company.id, # Crucial for event creation
            "approved": company.approved
        }
        token = create_access_token(identity=str(company.id), additional_claims=additional_claims) # Use 'token' as key
        return jsonify(token=token, role='company'), 200

    return jsonify({'error': 'Invalid credentials'}), 401


@auth_bp.route('/protected', methods=['GET'])
def protected():
    """Protected endpoint that requires valid JWT token"""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': 'Missing Authorization header'}), 401

    # Extract token (remove 'Bearer ' prefix if present)
    token = auth_header
    if token.startswith('Bearer '):
        token = token[7:]

    decoded = decode_token(token)
    if not decoded:
        return jsonify({'error': 'Invalid or expired token'}), 401

    return jsonify({
        'message': 'Access granted to protected resource',
        'user': {
            'email': decoded.get('email'),
            'role': decoded.get('role')
        },
        'token_expires': decoded.get('exp')
    }), 200