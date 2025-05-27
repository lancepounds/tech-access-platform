from flask import Blueprint, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from auth import jwt_required
from marshmallow import fields, validate, ValidationError
from main import db, User, ma
import jwt
import datetime
import os

users_bp = Blueprint('users', __name__)

# Validation schemas
class RegistrationSchema(ma.Schema):
    email = fields.Email(required=True,
        error_messages={
          "required": "Email is required.",
          "invalid": "Not a valid email address."
        })
    password = fields.String(required=True,
        validate=validate.Length(min=8),
        error_messages={
          "required": "Password is required.",
          "validator_failed": "Password must be at least 8 characters."
        })

class LoginSchema(ma.Schema):
    email = fields.Email(required=True,
        error_messages={"required": "Email is required."})
    password = fields.String(required=True,
        error_messages={"required": "Password is required."})

class ProfileSchema(ma.Schema):
    id = fields.Int(dump_only=True)
    email = fields.Email()
    role = fields.String()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()

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
    JWT_SECRET = os.environ.get('JWT_SECRET', 'fallback-jwt-secret')

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