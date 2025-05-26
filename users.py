
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime

users_bp = Blueprint('users', __name__)

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

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing email or password'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 400

    hashed_password = generate_password_hash(data['password'])
    new_user = User(
        email=data['email'],
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
    from main import JWT_SECRET
    
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing credentials'}), 400

    user = User.query.filter_by(email=data['email']).first()

    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401

    if not check_password_hash(user.password, data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = jwt.encode({
        'sub': user.id,
        'email': user.email,
        'role': user.role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, JWT_SECRET, algorithm='HS256')
    
    return jsonify({'token': token, 'role': user.role}), 200

@users_bp.route('/me', methods=['GET'])
def get_profile():
    User, db = get_user_model()
    from main import JWT_SECRET
    
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Missing token'}), 401

    # Remove 'Bearer ' prefix if present
    if token.startswith('Bearer '):
        token = token[7:]

    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = decoded.get('sub')
        
        if not user_id:
            return jsonify({'error': 'Invalid token format'}), 401
            
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        return jsonify({
            'id': user.id,
            'email': user.email,
            'role': user.role,
            'created_at': user.created_at.isoformat() if user.created_at else None
        }), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
