
from flask import Blueprint, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from auth import jwt_required
from marshmallow import Schema, fields, validate, ValidationError
import jwt
import datetime
import os

users_bp = Blueprint('users', __name__)

# Validation schemas
class RegisterSchema(Schema):
    email = fields.Email(required=True, error_messages={
        'required': 'Email is required',
        'invalid': 'Invalid email format'
    })
    password = fields.Str(required=True, validate=validate.Length(min=6), error_messages={
        'required': 'Password is required',
        'invalid': 'Password must be at least 6 characters long'
    })

class LoginSchema(Schema):
    email = fields.Email(required=True, error_messages={
        'required': 'Email is required',
        'invalid': 'Invalid email format'
    })
    password = fields.Str(required=True, error_messages={
        'required': 'Password is required'
    })

register_schema = RegisterSchema()
login_schema = LoginSchema()

def get_user_model():
    """Import User model to avoid circular imports"""
    from main import db
    
    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(120), unique=True, nullable=False)
        password = db.Column(db.String(128), nullable=False)
        role = db.Column(db.String(20), default='user')
        created_at = db.Column(db.DateTime, server_default=db.func.now())
        updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

        def __repr__(self):
            return f'<User {self.email}>'
    
    return User, db

@users_bp.route('/register', methods=['POST'])
def register():
    User, db = get_user_model()
    
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
    User, db = get_user_model()
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
