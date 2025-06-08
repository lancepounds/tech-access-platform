from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from app.models import User
from app.extensions import db, limiter # Import limiter
from app.users.schemas import RegistrationSchema, LoginSchema
from marshmallow import ValidationError
import jwt
import datetime
import os
import uuid
import json
import re
from config import Config

api_users_bp = Blueprint('api_users', __name__)

# JWT secret for token generation
JWT_SECRET = Config.JWT_SECRET

# REMOVED: ALLOWED_EXTENSIONS, allowed_file, validate_file_content (moved to app/utils/files.py)

def validate_password_strength(password):
    """Validate password meets security requirements."""
    if len(password) < 8:
        return False
    
    has_number = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    return has_number or has_special

@api_users_bp.route('/list', methods=['GET'])
def list_users():
    """Debug endpoint to see registered users"""
    users = User.query.all()
    user_list = [{'id': user.id, 'email': user.email, 'name': user.full_name, 'created_at': user.created_at} for user in users]
    return jsonify({'users': user_list, 'count': len(user_list)})

@api_users_bp.route('/register', methods=['GET'])
def show_register():
    return render_template('register.html')

@api_users_bp.route('/register', methods=['POST'])
@limiter.limit("5 per hour;20 per day")
def register():
    """Register a new user via JSON API."""
    if not request.is_json:
        return jsonify({'error': 'No JSON data provided'}), 400

    data = request.get_json() or {}
    try:
        validated = LoginSchema().load(data)
    except ValidationError as err:
        return jsonify({'error': 'Validation failed', 'details': err.messages}), 400

    if not validate_password_strength(validated['password']):
        return jsonify({
            'error': 'Validation failed',
            'details': {'password': ['Password must be at least 8 characters and include numbers or special characters']}
        }), 400

    email = validated['email'].strip().lower()
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 400

    hashed_password = generate_password_hash(validated['password'])
    user = User(email=email, password=hashed_password, role='user')
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@api_users_bp.route('/login', methods=['POST'])
def api_login():
    if not request.is_json:
        return jsonify({'error': 'No JSON data provided'}), 400

    data = request.get_json() or {}
    try:
        validated = LoginSchema().load(data)
    except ValidationError as err:
        return jsonify({'error': 'Validation failed', 'details': err.messages}), 400

    user = User.query.filter_by(email=validated['email']).first()
    if user and check_password_hash(user.password, validated['password']):
        token = jwt.encode({
            'email': user.email,
            'role': user.role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, JWT_SECRET, algorithm='HS256')
        return jsonify({'token': token, 'role': user.role}), 200

    return jsonify({'error': 'Invalid credentials'}), 401


@api_users_bp.route('/profile', methods=['GET'])
def profile():
    """Return the authenticated user's profile."""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': 'Missing Authorization header'}), 401

    token = auth_header[7:] if auth_header.startswith('Bearer ') else auth_header
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

    user = User.query.filter_by(email=decoded.get('email')).first()
    if not user:
        return jsonify({'error': 'Invalid token'}), 401

    return jsonify({
        'id': user.id,
        'email': user.email,
        'role': user.role,
        'created_at': user.created_at.isoformat(),
        'updated_at': user.updated_at.isoformat()
    }), 200
