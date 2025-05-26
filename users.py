
from flask import Blueprint, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from auth import jwt_required
from marshmallow import Schema, fields, validate, ValidationError
from main import db, User
import jwt
import datetime
import os

users_bp = Blueprint('users', __name__)

# Validation schemas
class RegisterSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=6))

class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True)

register_schema = RegisterSchema()
login_schema = LoginSchema()

@users_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400

    try:
        # Validate input using Marshmallow schema
        validated_data = register_schema.load(data)
    except ValidationError as e:
        return jsonify({'errors': e.messages}), 400

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
    JWT_SECRET = os.environ.get('JWT_SECRET', 'fallback-jwt-secret')
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400

    try:
        # Validate input using Marshmallow schema
        validated_data = login_schema.load(data)
    except ValidationError as e:
        return jsonify({'errors': e.messages}), 400

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
    
    return jsonify({
        'id': user.id,
        'email': user.email,
        'role': user.role,
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'updated_at': user.updated_at.isoformat() if user.updated_at else None
    }), 200
