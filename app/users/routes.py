import contextlib
import json
import os
import re
import uuid
from functools import wraps

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from app.extensions import db
from app.models import User
from config import Config

users_bp = Blueprint('users', __name__)

# JWT secret for token generation
JWT_SECRET = Config.JWT_SECRET

# Allowed file extensions for profile pictures
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    """Check if file extension is allowed for profile pictures."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_content(file):
    """Validate that uploaded file is actually an image."""
    try:
        # Check file signature (magic bytes)
        file.seek(0)
        header = file.read(512)
        file.seek(0)
        
        # Common image file signatures
        image_signatures = [
            b'\xff\xd8\xff',  # JPEG
            b'\x89PNG\r\n\x1a\n',  # PNG
            b'GIF87a',  # GIF87a
            b'GIF89a',  # GIF89a
            b'RIFF',  # WebP (contains RIFF)
        ]
        
        return any(header.startswith(sig) for sig in image_signatures)
    except Exception:
        return False

def validate_password_strength(password):
    """Validate password meets security requirements."""
    if len(password) < 8:
        return False
    
    has_number = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    return has_number or has_special

@users_bp.route('/list', methods=['GET'])
def list_users():
    """Debug endpoint to see registered users"""
    users = User.query.all()
    user_list = [
        {
            'id': user.id,
            'email': user.email,
            'name': user.full_name,
            'created_at': user.created_at
        }
        for user in users
    ]
    return jsonify({'users': user_list, 'count': len(user_list)})

@users_bp.route('/register', methods=['GET'])
def show_register():
    return render_template('register.html')

@users_bp.route('/register', methods=['POST'])
def register():
    # Handle different content types
    if request.is_json:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
    else:
        data = request.form
        if not data:
            flash('No form data provided', 'danger')
            return redirect(url_for('users.show_register'))

    # Validate required fields
    if not data.get('email') or not data.get('password'):
        error_msg = 'Missing email or password'
        if request.is_json:
            return jsonify({'error': error_msg}), 400
        flash(error_msg, 'danger')
        return redirect(url_for('users.show_register'))

    # All subsequent common validations need to check request.is_json
    # to return the correct error response type.

    email = data.get('email', '').strip().lower()
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        error_msg = 'Please provide a valid email address'
        if request.is_json:
            return jsonify({'error': error_msg}), 400
        else:
            flash(error_msg, 'danger')
            return redirect(url_for('users.show_register'))

    # Validate password confirmation
    # Ensure 'confirmPassword' is provided, especially for JSON requests if it's expected
    if data.get('password') != data.get('confirmPassword'): # For JSON, ensure confirmPassword is part of the payload
        error_msg = 'Passwords do not match'
        if request.is_json:
            return jsonify({'error': error_msg}), 400
        else:
            flash(error_msg, 'danger')
            return redirect(url_for('users.show_register'))

    # Validate password strength
    if not validate_password_strength(data['password']):
        error_msg = (
            'Password must be at least 8 characters and '
            'include numbers or special characters'
        )
        if request.is_json:
            return jsonify({'error': error_msg}), 400
        else:
            flash(error_msg, 'danger')
            return redirect(url_for('users.show_register'))

    # Check if user already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        error_msg = 'User already exists'
        if request.is_json:
            return jsonify({'error': error_msg}), 400
        else:
            flash(error_msg, 'danger')
            return redirect(url_for('users.show_register'))

    # Process disabilities and interests (handle multiple selections)
    disabilities = []
    interests = []
    specific_disability = None
    profile_picture_filename = None
    
    if not request.is_json:
        # Handle form data (multiple selections)
        disabilities = (
            request.form.getlist('disabilities')
            if 'disabilities' in request.form else []
        )
        interests = (
            request.form.getlist('interests')
            if 'interests' in request.form else []
        )
        specific_disability = request.form.get('specificDisability')
        
        # Handle profile picture upload
        if 'profilePicture' in request.files:
            file = request.files['profilePicture']
            if file and file.filename:
                # Validate file extension
                if not allowed_file(file.filename):
                    flash(
                        ('Invalid file type. Please upload PNG, JPG, GIF, '
                         'or WebP images only.'),
                        'danger'
                    )
                    return redirect(url_for('users.show_register'))
                
                # Validate file size (5MB limit) - check actual file size
                file.seek(0, os.SEEK_END)
                file_size = file.tell()
                file.seek(0)
                if file_size > 5 * 1024 * 1024:
                    flash('File size must be less than 5MB.', 'danger')
                    return redirect(url_for('users.show_register'))
                
                # Validate file content
                if not validate_file_content(file):
                    flash('Invalid image file. Please upload a valid image.', 'danger')
                    return redirect(url_for('users.show_register'))
                
                # Create uploads directory if it doesn't exist
                upload_dir = os.path.join('static', 'uploads', 'profiles')
                os.makedirs(upload_dir, exist_ok=True)
                
                # Generate unique filename
                filename = secure_filename(file.filename)
                name, ext = os.path.splitext(filename)
                unique_filename = f"{str(uuid.uuid4())}{ext}"
                file_path = os.path.join(upload_dir, unique_filename)
                
                try:
                    file.save(file_path)
                    profile_picture_filename = unique_filename
                except Exception:
                    flash(
                        'Error uploading profile picture. Please try again.',
                        'danger'
                    )
                    return redirect(url_for('users.show_register'))
    else:
        # Handle JSON data
        disabilities = data.get('disabilities', [])
        interests = data.get('interests', [])
        specific_disability = data.get('specificDisability')

    # Create new user
    hashed_password = generate_password_hash(data['password'])
    new_user = User(
        email=email,
        password=hashed_password,
        role='user',
        first_name=data.get('firstName'),
        last_name=data.get('lastName'),
        phone=data.get('phone'),
        disabilities=json.dumps(disabilities) if disabilities else None,
        specific_disability=specific_disability,
        assistive_tech=data.get('assistiveTech'),
        tech_experience=data.get('techExperience'),
        interests=json.dumps(interests) if interests else None,
        email_notifications=bool(data.get('emailNotifications')),
        newsletter_subscription=bool(data.get('newsletter')),
        profile_picture=profile_picture_filename
    )

    try:
        db.session.add(new_user)
        db.session.commit()

        if request.is_json:
            return jsonify({'message': 'User created successfully'}), 201

        flash('Registration successful! Welcome to Tech Access Group.', 'success')
        return redirect(url_for('auth.login'))
    except Exception:
        db.session.rollback()
        # Clean up uploaded file if user creation fails
        if profile_picture_filename:
            with contextlib.suppress(Exception):
                os.remove(
                    os.path.join(
                        'static', 'uploads', 'profiles', profile_picture_filename
                    )
                )
        
        error_msg = 'Registration failed. Please try again.'
        if request.is_json:
            return jsonify({'error': error_msg}), 500
        flash(error_msg, 'danger')
        return redirect(url_for('users.show_register'))

# Placeholder for JWT-based authentication/user loading
# In a real app, this would come from app.auth.decorators or similar
def jwt_required_placeholder():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            # This is a mock, replace with actual token validation
            # and user loading (e.g., using flask_jwt_extended)
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Missing or malformed Authorization header'}), 401

            # Mock: assume token is valid and extract user identity (e.g., email)
            # In a real app, you'd decode and verify the token here
            # For testing, we'll assume a valid token if present
            # and that get_jwt_identity_placeholder exists and returns a mock email
            # current_user_email = get_jwt_identity_placeholder()
            # For now, let's just pass if token exists
            pass # Replace with actual user loading based on token
            return fn(*args, **kwargs) # In real app: fn(current_user, *args, **kwargs)
        return decorator
    return wrapper

# Placeholder for getting current user identity from token
# def get_jwt_identity_placeholder():
#     return "mockuser@example.com" # Replace with actual logic

@users_bp.route('/profile', methods=['GET'])
@jwt_required_placeholder() # This is a placeholder decorator
def get_user_profile():
    # In a real implementation, current_user would be loaded by jwt_required
    # For now, assume a mock current_user or fetch based on a mock identity
    # current_user_email = get_jwt_identity_placeholder()
    # user = User.query.filter_by(email=current_user_email).first()
    # if not user:
    #    return jsonify({'error': 'User not found'}), 404

    # Placeholder response
    return jsonify({
        'message': 'Profile endpoint reached (mock)',
        # 'user_email': current_user_email # If you use the mock identity
    }), 200
