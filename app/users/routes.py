from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User
from app.extensions import db
import jwt
import datetime
from config import Config

users_bp = Blueprint('users', __name__)

# JWT secret for token generation
JWT_SECRET = Config.JWT_SECRET

@users_bp.route('/register', methods=['GET'])
def show_register():
    return render_template('register.html')

@users_bp.route('/register', methods=['POST'])
def register():
    import json
    
    data = request.get_json() if request.is_json else request.form

    if not data or not data.get('email') or not data.get('password'):
        if request.is_json:
            return jsonify({'error': 'Missing email or password'}), 400
        flash('Missing email or password', 'danger')
        return redirect(url_for('users.show_register'))

    # Check if user already exists
    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        if request.is_json:
            return jsonify({'error': 'User already exists'}), 400
        flash('User already exists', 'danger')
        return redirect(url_for('users.show_register'))

    # Process disabilities and interests (handle multiple selections)
    disabilities = []
    interests = []
    
    if not request.is_json:
        # Handle form data (multiple selections)
        disabilities = request.form.getlist('disabilities') if 'disabilities' in request.form else []
        interests = request.form.getlist('interests') if 'interests' in request.form else []
    else:
        # Handle JSON data
        disabilities = data.get('disabilities', [])
        interests = data.get('interests', [])

    # Create new user
    hashed_password = generate_password_hash(data['password'])
    new_user = User(
        email=data['email'],
        password=hashed_password,
        role='user',
        first_name=data.get('firstName'),
        last_name=data.get('lastName'),
        phone=data.get('phone'),
        disabilities=json.dumps(disabilities) if disabilities else None,
        assistive_tech=data.get('assistiveTech'),
        tech_experience=data.get('techExperience'),
        interests=json.dumps(interests) if interests else None,
        email_notifications=bool(data.get('emailNotifications')),
        newsletter_subscription=bool(data.get('newsletter'))
    )

    try:
        db.session.add(new_user)
        db.session.commit()

        if request.is_json:
            return jsonify({'message': 'User created successfully'}), 201

        flash('Registration successful! Welcome to Tech Access Group.', 'success')
        return redirect(url_for('auth.login_page'))
    except Exception as e:
        db.session.rollback()
        if request.is_json:
            return jsonify({'error': f'Failed to create user: {str(e)}'}), 500
        flash('Registration failed. Please try again.', 'danger')
        return redirect(url_for('users.show_register'))