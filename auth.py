
from functools import wraps
from flask import request, jsonify, g
import jwt
import os

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

def jwt_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        User, db = get_user_model()
        
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Missing Authorization header'}), 401
        
        # Extract token (remove 'Bearer ' prefix if present)
        token = auth_header
        if token.startswith('Bearer '):
            token = token[7:]
        
        try:
            # Decode the JWT token
            JWT_SECRET = os.environ.get('JWT_SECRET', 'fallback-jwt-secret')
            decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            user_id = decoded.get('sub')
            
            if not user_id:
                return jsonify({'error': 'Invalid token format'}), 401
            
            # Load user by ID
            user = User.query.get(user_id)
            if not user:
                return jsonify({'error': 'User not found'}), 401
            
            # Store user in flask.g for access in route handlers
            g.current_user = user
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function
