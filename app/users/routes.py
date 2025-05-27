
from flask import Blueprint, request, jsonify, g, render_template, flash, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from app.auth.decorators import jwt_required
from app.users.schemas import RegistrationSchema, LoginSchema, ProfileSchema
from marshmallow import ValidationError
from app.models import User
from app.extensions import db
import jwt
import datetime
import os

users_bp = Blueprint('users', __name__)

JWT_SECRET = os.environ.get('JWT_SECRET', 'fallback-jwt-secret')

registration_schema = RegistrationSchema()
login_schema = LoginSchema()
profile_schema = ProfileSchema()


@users_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400

    try:
        # Validate input using Marshmallow schema
        validated_data = registration_schema.load(data)
    except ValidationError as e:
        return jsonify({
            'error': 'Validation failed',
            'details': e.messages
        }), 400

    if User.query.filter_by(email=validated_data['email']).first():
        return jsonify({'error': 'Email already registered'}), 400

    hashed_password = generate_password_hash(validated_data['password'])
    new_user = User(
        email=validated_data['email'],
        password=hashed_password,
        role='user'
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Registration failed'}), 500


@users_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400

    try:
        # Validate input using Marshmallow schema
        validated_data = login_schema.load(data)
    except ValidationError as e:
        return jsonify({
            'error': 'Validation failed',
            'details': e.messages
        }), 400

    user = User.query.filter_by(email=validated_data['email']).first()

    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401

    if not check_password_hash(user.password, validated_data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = jwt.encode({
        'sub': user.id,
        'email': user.email,
        'role': user.role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, JWT_SECRET, algorithm='HS256')

    return jsonify({'token': token, 'role': user.role}), 200


@users_bp.route('/profile', methods=['GET'])
@jwt_required
def get_profile():
    # User is now available in g.current_user thanks to the decorator
    user = g.current_user

    # Use ProfileSchema to serialize the user data
    result = profile_schema.dump(user)
    return jsonify(result), 200


@users_bp.route('/register', methods=['GET', 'POST'])
def show_register():
    if request.method == 'GET':
        return render_template('register.html')
    
    # Handle POST request from form
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirmPassword')
    
    # Validation
    if not email or not password or not confirm_password:
        flash('All fields are required.', 'danger')
        return render_template('register.html')
    
    if password != confirm_password:
        flash('Passwords do not match.', 'danger')
        return render_template('register.html')
    
    # Check if email already exists
    if User.query.filter_by(email=email).first():
        flash('Email already registered.', 'danger')
        return render_template('register.html')
    
    # Create new user
    try:
        hashed_password = generate_password_hash(password)
        new_user = User(
            email=email,
            password=hashed_password,
            role='user'
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login_page'))
    except Exception as e:
        db.session.rollback()
        flash('Registration failed. Please try again.', 'danger')
        return render_template('register.html')
