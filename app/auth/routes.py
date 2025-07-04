from flask import Blueprint, request, jsonify, render_template, session, flash, redirect, url_for, current_app
from werkzeug.security import check_password_hash, generate_password_hash
from app.models import User, Company
from .forms import LoginForm, ForgotPasswordForm, ResetPasswordForm
from flask_login import login_user, logout_user # login_user is used
from flask_jwt_extended import create_access_token
from app.auth.decorators import decode_token
from app.email_service import send_email
import secrets
from app.extensions import db, limiter # Import limiter
from sqlalchemy.exc import IntegrityError
import jwt
import datetime # datetime is used
import os
import logging

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

JWT_SECRET = os.environ.get('JWT_SECRET')
if JWT_SECRET is None:
    JWT_SECRET = 'fallback-jwt-secret'
    logging.warning("SECURITY WARNING: Using default JWT_SECRET. This should be changed for production environments.")

# Helper function for token verification
def verify_reset_token(token):
    try:
        user = User.query.filter_by(reset_token=token).first()
        if user and user.reset_token_expiration > datetime.datetime.utcnow():
            return user
    except Exception as e: # Broad exception for safety, log this
        current_app.logger.error(f"Error verifying reset token: {e}")
    return None

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

    db.session.add(new_user)

    new_company = None
    if role == 'company':
        # Use email prefix as default company name if 'company_name' not provided
        company_name = data.get('company_name', data['email'].split('@')[0] + " (Default Name)")
        new_company = Company(
            name=company_name,
            contact_email=new_user.email,
            password=hashed_password,  # Using user's hashed password for company entity as per plan
            approved=False # Companies start as not approved
        )
        db.session.add(new_company)

    try:
        db.session.commit()

        # Log in the user
        login_user(new_user)

        # Set up session variables
        session['email'] = new_user.email
        session['role'] = new_user.role

        token_payload = {
            'email': new_user.email,
            'role': new_user.role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }

        if new_user.role == 'company' and new_company:
            session['company_id'] = new_company.id
            token_payload['company_id'] = new_company.id

        token = jwt.encode(token_payload, JWT_SECRET, algorithm='HS256')
        session['token'] = token

        if new_user.role == 'company':
            flash('Registration successful. Please complete your company profile if prompted. Approval may be required for full functionality.', 'info')
            return redirect(url_for('dashboard.company_dashboard'))
        else: # 'user' role
            # flash('User registered successfully!', 'success') # Optional: flash message for user
            return redirect(url_for('dashboard.member_dashboard'))

    except IntegrityError as e:
        db.session.rollback()
        logging.error(f"IntegrityError during user registration: {str(e)}")
        # Check if the error is due to company name or email already existing
        if new_company and Company.query.filter((Company.name == new_company.name) | (Company.contact_email == new_company.contact_email)).first():
             return jsonify({'error': 'Company name or contact email already exists.'}), 400
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


@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("5 per hour") # Adding rate limiting
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            # Use current_app.config for expiration duration
            expires_hours = current_app.config.get('PASSWORD_RESET_TOKEN_EXPIRES_HOURS', 1)
            user.reset_token_expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=expires_hours)
            db.session.commit()

            reset_url = url_for('auth.reset_password_with_token', token=token, _external=True)
            html_content = render_template('email/reset_password_email.html',
                                           reset_url=reset_url,
                                           user=user,
                                           expires_hours=expires_hours)
            send_email(user.email, 'Password Reset Request', html_content)

        flash('If an account with that email exists, a password reset link has been sent.', 'info')
        return redirect(url_for('auth.login'))
    return render_template('auth/forgot_password.html', form=form, title='Forgot Password')


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
@limiter.limit("5 per hour") # Adding rate limiting
def reset_password_with_token(token):
    user = verify_reset_token(token)
    if not user:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = generate_password_hash(form.password.data)
        user.reset_token = None
        user.reset_token_expiration = None
        db.session.commit()
        flash('Your password has been successfully reset. Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/reset_password.html', form=form, token=token, title='Reset Password')


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