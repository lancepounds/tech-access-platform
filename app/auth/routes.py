from flask import Blueprint, request, jsonify, render_template, session, flash, redirect, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from app.models import User, Company
from .forms import LoginForm
from flask_login import login_user, logout_user
from flask_jwt_extended import create_access_token
from app.auth.decorators import decode_token
from app.extensions import db, limiter # Import limiter
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
@limiter.limit("5 per hour;20 per day")
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
@limiter.limit("10 per minute;20 per hour")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)  # Log in the user with Flask-Login

            session['email'] = user.email # Common session vars
            session['role'] = user.role   # Common session vars

            if user.role == 'company':
                company_obj = Company.query.filter_by(contact_email=user.email).first()
                if company_obj and company_obj.approved:
                    session['company_id'] = company_obj.id
                    token = jwt.encode({
                        'email': user.email,
                        'role': user.role,
                        'company_id': company_obj.id,
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
                    }, JWT_SECRET, algorithm='HS256')
                    session['token'] = token
                    flash('Company login successful.', 'success')
                    return redirect(url_for('dashboard.company_dashboard'))
                elif company_obj and not company_obj.approved:
                    logout_user()
                    session.clear()
                    flash('Your company account is pending approval. Please wait for admin approval.', 'warning')
                    return render_template('login.html', form=form)
                else:
                    logout_user()
                    session.clear()
                    flash('Company details not found for this user. Ensure your company is registered and approved.', 'danger')
                    return render_template('login.html', form=form)
            else:  # Regular user or other non-company roles
                token = jwt.encode({
                    'email': user.email,
                    'role': user.role,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
                }, JWT_SECRET, algorithm='HS256')
                session['token'] = token
                flash('Logged in successfully', 'success')
                return redirect(url_for('main.show_events'))

        # If user not found by email, or password incorrect, try company login by contact_email as a fallback
        # This part of the original logic might be redundant if all company reps are Users with role='company'
        # For now, retaining a modified version of it.
        # However, this block will NOT call login_user() and thus current_user won't be set for these.
        # This could be an issue for @login_required routes if this path is taken.
        # The preferred path is for a User with role='company' to exist.
        company_as_entity = Company.query.filter_by(contact_email=email).first()
        if company_as_entity and check_password_hash(company_as_entity.password, password) and not user: # Only if no user matched
            if not company_as_entity.approved:
                flash('Your company account is pending approval. Please wait for admin approval.', 'warning')
                return render_template('login.html', form=form)

            # This path does not use flask_login.login_user(). current_user will not be set.
            # Only session variables are set. This is suitable for non-Flask-Login based auth checks.
            session['email'] = company_as_entity.contact_email
            session['role'] = company_as_entity.role # This is 'company'
            session['company_id'] = company_as_entity.id
            token = jwt.encode({
                'email': company_as_entity.contact_email,
                'role': company_as_entity.role,
                'company_id': company_as_entity.id,
                'approved': company_as_entity.approved,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, JWT_SECRET, algorithm='HS256')
            session['token'] = token
            flash('Company entity login successful (session only).', 'success') # Differentiate this login
            return redirect(url_for('dashboard.company_dashboard'))

        flash('Invalid credentials', 'danger')

    return render_template('login.html', form=form)


@auth_bp.route('/logout', methods=['POST'])
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('main.index'))


@auth_bp.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute;20 per hour")
def api_login():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing credentials'}), 400

    user = User.query.filter_by(email=data['email']).first()
    company = Company.query.filter_by(contact_email=data['email']).first()

    if user and check_password_hash(user.password, data['password']):
        # Identity can be user.id or user.email, depending on setup.
        # flask-jwt-extended uses 'sub' claim for identity.
        additional_claims = {"role": user.role, "email": user.email}
        if user.role == 'company':
            company_obj = Company.query.filter_by(contact_email=user.email).first()
            if company_obj and company_obj.approved: # Ensure company is approved
                additional_claims["company_id"] = company_obj.id
            elif company_obj and not company_obj.approved: # Company exists but not approved
                return jsonify({"error": "Company account not approved"}), 403
            else: # No company record found for this user claiming to be a company
                return jsonify({"error": "Company details not found for this user"}), 403

        token = create_access_token(identity=str(user.id), additional_claims=additional_claims)
        # Return the role that was put into the token
        return jsonify(token=token, role=additional_claims.get("role", user.role)), 200

    # Fallback for direct Company login (if no User record with that email)
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