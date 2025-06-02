from flask import Blueprint, request, jsonify, render_template, session, flash, redirect, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from app.models import User, Company
from app.auth.decorators import decode_token
from app.extensions import db
import jwt
import datetime
import os

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

JWT_SECRET = os.environ.get('JWT_SECRET', 'fallback-jwt-secret')


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
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to create user: {str(e)}'}), 500


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    # Handle POST request from form
    email = request.form.get('email')
    password = request.form.get('password')

    # Validation
    if not email or not password:
        flash('Missing credentials', 'danger')
        return render_template('login.html')

    # Use existing JWT login logic
    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password, password):
        # Generate JWT token for user
        token = jwt.encode({
            'email': user.email,
            'role': user.role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, JWT_SECRET, algorithm='HS256')

        # Store login info in session
        session['token'] = token
        session['email'] = user.email
        session['role'] = user.role

        flash('Logged in successfully', 'success')
        return redirect(url_for('main.show_events'))

    # Check if it's a company login
    company = Company.query.filter_by(contact_email=email).first()
    if company and check_password_hash(company.password, password):
        if not company.approved:
            flash('Your company account is pending approval. Please wait for admin approval.', 'warning')
            return render_template('login.html')

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
    return render_template('login.html')


@auth_bp.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('main.index'))


@auth_bp.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing credentials'}), 400

    user = User.query.filter_by(email=data['email']).first()
    company = Company.query.filter_by(name=data['email']).first()

    if user and check_password_hash(user.password, data['password']):
        token = jwt.encode({
            'email': user.email,
            'role': user.role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, JWT_SECRET, algorithm='HS256')
        return jsonify({'token': token, 'role': 'user'}), 200

    if company and data['password'] == company.password:
        # For companies, we use their name as both email and password
        if data['password'] == company.name:
            token = jwt.encode({
                'email': company.name,
                'role': company.role,
                'approved': company.approved,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, JWT_SECRET, algorithm='HS256')
            return jsonify({'token': token, 'role': 'company'}), 200

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