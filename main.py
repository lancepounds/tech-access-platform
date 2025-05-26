from flask import Flask, request, jsonify, render_template, url_for, flash, redirect, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import uuid
import os

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
import os

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-secret-key')
app.secret_key = os.environ.get('SECRET_KEY', 'fallback-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///:memory:')
db = SQLAlchemy(app)

JWT_SECRET = os.environ.get('JWT_SECRET', 'fallback-jwt-secret')

# User model will be defined inline to avoid circular imports

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    def __repr__(self):
        return f'<User {self.email}>'

class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), default='company')
    approved = db.Column(db.Boolean, default=False)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    company = db.relationship('Company', backref=db.backref('events', lazy=True))

class RSVP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    user_email = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    fulfilled = db.Column(db.Boolean, default=False)

    __table_args__ = (
        db.UniqueConstraint('event_id', 'user_email', name='unique_rsvp'),
    )

class Reward(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rsvp_id = db.Column(db.Integer, db.ForeignKey('rsvp.id'), nullable=False)
    code = db.Column(db.String(36), unique=True, nullable=False)
    value_cents = db.Column(db.Integer, nullable=False, default=1000)  # $10
    issued_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    redeemed = db.Column(db.Boolean, default=False)
    rsvp = db.relationship('RSVP', backref='reward', uselist=False)

with app.app_context():
    db.create_all()

# Global error handler for Marshmallow ValidationError
from marshmallow import ValidationError

@app.errorhandler(ValidationError)
def handle_validation_error(e):
    return jsonify({'error': 'Validation failed', 'details': e.messages}), 400

# Register Blueprint
from users import users_bp
app.register_blueprint(users_bp, url_prefix='/api/users')

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing credentials'}), 400

    user = User.query.filter_by(email=data['email']).first()
    company = Company.query.filter_by(name=data['email']).first()

    if user and check_password_hash(user.password, data['password']):
        token = jwt.encode({
            'email': user.email,
            'role': user.role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, JWT_SECRET, algorithm='HS256')
        return jsonify({'token': token, 'role': 'user'}), 200

    if company and data['password'] == company.password:
    # For companies, we use their name as both email and password
        if data['password'] == company.name:
            token = jwt.encode({
                'email': company.name,
                'role': company.role,
                'approved': company.approved,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, JWT_SECRET, algorithm='HS256')
            return jsonify({'token': token, 'role': 'company'}), 200

    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/user/register', methods=['POST'])
def register():
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

# Simple admin token (in production, use real authentication)
ADMIN_TOKEN = "my-secret-admin-token"

@app.route('/admin/pending_companies', methods=['GET'])
def list_pending_companies():
    token = request.headers.get('Authorization')
    if token != f"Bearer {ADMIN_TOKEN}":
        return jsonify({'error': 'Unauthorized'}), 403

    pending = Company.query.filter_by(approved=False).all()
    result = [{'id': c.id, 'name': c.name} for c in pending]
    return jsonify(result), 200

@app.route('/admin/approve_company', methods=['POST'])
def approve_company():
    token = request.headers.get('Authorization')
    if token != f"Bearer {ADMIN_TOKEN}":
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    company_name = data.get('name')

    if not company_name:
        return jsonify({'error': 'Missing company name'}), 400

    company = Company.query.filter_by(name=company_name).first()
    if not company:
        return jsonify({'error': 'Company not found'}), 404

    if company.approved:
        return jsonify({'message': 'Company already approved'}), 200

    company.approved = True
    try:
        db.session.commit()
        return jsonify({'message': f'Company {company_name} approved'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to approve company: {str(e)}'}), 500

@app.route('/events', methods=['GET', 'POST'])
def events():
    if request.method == 'GET':
        events = Event.query.join(Company).all()
        return jsonify([{
            'id': event.id,
            'title': event.title,
            'description': event.description,
            'date': event.date.isoformat(),
            'company_name': event.company.name
        } for event in events]), 200

    # POST method handling
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Missing token'}), 401

    decoded = decode_token(token)
    if not decoded:
        return jsonify({'error': 'Invalid token'}), 401

    if decoded['role'] != 'company':
        return jsonify({'error': 'Unauthorized'}), 403

    company = Company.query.filter_by(name=decoded['email']).first()
    if not company:
        return jsonify({'error': 'Company not found'}), 404
    if not company.approved:
        return jsonify({'error': 'Company not approved'}), 403

    data = request.get_json()
    required_fields = ['title', 'description', 'date']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        event_date = datetime.fromisoformat(data['date'].replace('Z', '+00:00'))
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use ISO format'}), 400

    new_event = Event(
        title=data['title'],
        description=data['description'],
        date=event_date,
        company_id=company.id
    )

    try:
        db.session.add(new_event)
        db.session.commit()
        return jsonify({
            'message': 'Event created successfully',
            'id': new_event.id
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to create event: {str(e)}'}), 500

@app.route('/events/<int:event_id>/rsvp', methods=['POST'])
def rsvp_event(event_id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Missing token'}), 401

    decoded = decode_token(token)
    if not decoded:
        return jsonify({'error': 'Invalid token'}), 401

    if decoded['role'] != 'user':
        return jsonify({'error': 'Unauthorized'}), 403

    user = User.query.filter_by(email=decoded['email']).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    event = Event.query.get(event_id)
    if not event:
        return jsonify({'error': 'Event not found'}), 404

    try:
        new_rsvp = RSVP(event_id=event_id, user_email=decoded['email'])
        db.session.add(new_rsvp)
        db.session.commit()
        return jsonify({'message': 'RSVP successful'}), 201
    except Exception as e:
        db.session.rollback()
        if 'UNIQUE constraint failed' in str(e):
            return jsonify({'error': 'You have already RSVP\'d for this event'}), 400
        return jsonify({'error': f'Failed to RSVP: {str(e)}'}), 500

@app.route('/events/<int:event_id>/rsvps', methods=['GET'])
def get_event_rsvps(event_id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Missing token'}), 401

    decoded = decode_token(token)
    if not decoded or decoded['role'] != 'company':
        return jsonify({'error': 'Unauthorized'}), 403

    company = Company.query.filter_by(name=decoded['email']).first()
    if not company or not company.approved:
        return jsonify({'error': 'Company not found or not approved'}), 403

    event = Event.query.get(event_id)
    if not event or event.company_id != company.id:
        return jsonify({'error': 'Event not found or does not belong to your company'}), 404

    rsvps = RSVP.query.filter_by(event_id=event_id).all()
    return jsonify([{
        'user_email': rsvp.user_email,
        'timestamp': rsvp.created_at.isoformat(),
        'fulfilled': rsvp.fulfilled
    } for rsvp in rsvps]), 200


@app.route('/rsvps/<int:rsvp_id>/fulfill', methods=['POST'])
def fulfill_rsvp(rsvp_id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Missing token'}), 401

    decoded = decode_token(token)
    if not decoded or decoded['role'] != 'company':
        return jsonify({'error': 'Unauthorized'}), 403

    company = Company.query.filter_by(name=decoded['email']).first()
    if not company or not company.approved:
        return jsonify({'error': 'Company not found or not approved'}), 403

    rsvp = RSVP.query.get(rsvp_id)
    if not rsvp:
        return jsonify({'error': 'RSVP not found'}), 404

    event = Event.query.get(rsvp.event_id)
    if event.company_id != company.id:
        return jsonify({'error': 'This RSVP does not belong to one of your events'}), 403

    rsvp.fulfilled = True

    try:
        db.session.commit()
        return jsonify({'message': f'RSVP for {rsvp.user_email} marked as fulfilled'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to update RSVP: {str(e)}'}), 500


@app.route('/events/<int:event_id>/rsvp-ui', methods=['POST'])
def rsvp_event_ui(event_id):
    # Check if user is logged in via session
    if 'token' not in session or 'role' not in session:
        flash('Please log in to RSVP for events.', 'danger')
        return redirect(url_for('login_page'))
    
    if session['role'] != 'user':
        flash('Only users can RSVP for events.', 'danger')
        return redirect(url_for('show_events'))
    
    # Decode token to get user info
    decoded = decode_token(session['token'])
    if not decoded:
        flash('Session expired. Please log in again.', 'danger')
        return redirect(url_for('login_page'))
    
    user = User.query.filter_by(email=decoded['email']).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('show_events'))
    
    event = Event.query.get(event_id)
    if not event:
        flash('Event not found.', 'danger')
        return redirect(url_for('show_events'))
    
    try:
        new_rsvp = RSVP(event_id=event_id, user_email=decoded['email'])
        db.session.add(new_rsvp)
        db.session.commit()
        flash('RSVP successful!', 'success')
    except Exception as e:
        db.session.rollback()
        if 'UNIQUE constraint failed' in str(e):
            flash('You have already RSVP\'d for this event.', 'warning')
        else:
            flash('Failed to RSVP. Please try again.', 'danger')
    
    return redirect(url_for('show_events'))

@app.route('/my-rsvps', methods=['GET'])
def get_my_rsvps():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Missing token'}), 401

    decoded = decode_token(token)
    if not decoded:
        return jsonify({'error': 'Invalid token'}), 401

    if decoded['role'] != 'user':
        return jsonify({'error': 'Unauthorized'}), 403

    rsvps = RSVP.query.filter_by(user_email=decoded['email']).all()
    events = []
    for rsvp in rsvps:
        event = Event.query.get(rsvp.event_id)
        if event:
            events.append({
                'id': event.id,
                'title': event.title,
                'description': event.description,
                'date': event.date.isoformat(),
                'company_name': event.company.name,
                'rsvp_date': rsvp.created_at.isoformat()
            })

    return jsonify(events), 200

@app.route('/my-rsvps-page')
def show_my_rsvps():
    # Check if user is logged in via session
    if 'token' not in session or 'role' not in session:
        flash('Please log in to view your RSVPs.', 'danger')
        return redirect(url_for('login_page'))
    
    if session['role'] != 'user':
        flash('Only users can view RSVPs.', 'danger')
        return redirect(url_for('show_events'))
    
    # Decode token to get user info
    decoded = decode_token(session['token'])
    if not decoded:
        flash('Session expired. Please log in again.', 'danger')
        return redirect(url_for('login_page'))
    
    # Query RSVPs for the logged-in user
    rsvps = RSVP.query.filter_by(user_email=decoded['email']).join(Event).join(Company).all()
    
    return render_template('my_rsvps.html', rsvps=rsvps)

@app.route('/dashboard')
def company_dashboard():
    if session.get('role') != 'company':
        flash('Please log in as a company.', 'danger')
        return redirect(url_for('login_page'))
    decoded = decode_token(session['token'])
    company = Company.query.filter_by(name=decoded['email']).first()
    return render_template('company_dashboard.html', events=company.events)

@app.route('/company-dashboard')
def company_dashboard_legacy():
    # Check if company is logged in via session
    if 'token' not in session or 'role' not in session:
        flash('Please log in to view your dashboard.', 'danger')
        return redirect(url_for('login_page'))
    
    if session['role'] != 'company':
        flash('Only companies can view the dashboard.', 'danger')
        return redirect(url_for('show_events'))
    
    # Decode token to get company info
    decoded = decode_token(session['token'])
    if not decoded:
        flash('Session expired. Please log in again.', 'danger')
        return redirect(url_for('login_page'))
    
    company = Company.query.filter_by(name=decoded['email']).first()
    if not company:
        flash('Company not found.', 'danger')
        return redirect(url_for('show_events'))
    
    if not company.approved:
        flash('Company not approved.', 'danger')
        return redirect(url_for('show_events'))
    
    # Query events for the logged-in company with their RSVPs
    events = Event.query.filter_by(company_id=company.id).all()
    
    # Load RSVPs for each event
    for event in events:
        event.rsvps = RSVP.query.filter_by(event_id=event.id).all()
    
    return render_template('company_dashboard.html', events=events)

@app.route('/rsvps/<int:rsvp_id>/fulfill-ui', methods=['POST'])
def fulfill_rsvp_ui(rsvp_id):
    # Check if company is logged in via session
    if 'token' not in session or 'role' not in session:
        flash('Please log in to fulfill RSVPs.', 'danger')
        return redirect(url_for('login_page'))
    
    if session['role'] != 'company':
        flash('Only companies can fulfill RSVPs.', 'danger')
        return redirect(url_for('show_events'))
    
    # Decode token to get company info
    decoded = decode_token(session['token'])
    if not decoded:
        flash('Session expired. Please log in again.', 'danger')
        return redirect(url_for('login_page'))
    
    company = Company.query.filter_by(name=decoded['email']).first()
    if not company or not company.approved:
        flash('Company not found or not approved.', 'danger')
        return redirect(url_for('show_events'))
    
    rsvp = RSVP.query.get(rsvp_id)
    if not rsvp:
        flash('RSVP not found.', 'danger')
        return redirect(url_for('company_dashboard'))
    
    event = Event.query.get(rsvp.event_id)
    if event.company_id != company.id:
        flash('This RSVP does not belong to one of your events.', 'danger')
        return redirect(url_for('company_dashboard'))
    
    if rsvp.fulfilled:
        flash('RSVP is already fulfilled.', 'info')
        return redirect(url_for('company_dashboard'))
    
    rsvp.fulfilled = True
    
    try:
        db.session.commit()
        flash(f'RSVP for {rsvp.user_email} marked as fulfilled!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Failed to update RSVP. Please try again.', 'danger')
    
    return redirect(url_for('company_dashboard'))

@app.route('/rsvps/<int:rsvp_id>/issue-gift', methods=['POST'])
def issue_gift(rsvp_id):
    # Only companies can issue gifts
    if session.get('role') != 'company':
        flash('Please log in as a company.', 'danger')
        return redirect(url_for('login_page'))

    decoded = decode_token(session['token'])
    company = Company.query.filter_by(name=decoded['email']).first()
    if not company or not company.approved:
        flash('Not authorized.', 'danger')
        return redirect(url_for('login_page'))

    rsvp = RSVP.query.get_or_404(rsvp_id)
    if rsvp.fulfilled:
        flash('Gift already issued.', 'warning')
        return redirect(url_for('company_dashboard'))

    # Generate and save gift code
    code = str(uuid.uuid4())
    reward = Reward(rsvp_id=rsvp.id, code=code)
    rsvp.fulfilled = True

    db.session.add_all([reward, rsvp])
    db.session.commit()

    flash(f'Gift code issued: {code}', 'success')
    return redirect(url_for('company_dashboard'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'GET':
        return render_template('login.html')
    
    # Handle POST request from form
    email = request.form.get('email')
    password = request.form.get('password')
    
    # Validation
    if not email or not password:
        flash('Missing credentials', 'danger')
        return render_template('login.html')

    # Use existing JWT login logic
    user = User.query.filter_by(email=email).first()
    company = Company.query.filter_by(name=email).first()

    if user and check_password_hash(user.password, password):
        # Generate JWT token for user
        token = jwt.encode({
            'email': user.email,
            'role': user.role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, JWT_SECRET, algorithm='HS256')
        
        # Store login info in session
        session['token'] = token
        session['email'] = user.email
        session['role'] = user.role
        
        flash('Logged in successfully', 'success')
        return redirect(url_for('show_events'))

    if company and password == company.password:
        # For companies, we use their name as both email and password
        if password == company.name:
            # Generate JWT token for company
            token = jwt.encode({
                'email': company.name,
                'role': company.role,
                'approved': company.approved,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, JWT_SECRET, algorithm='HS256')
            
            # Store login info in session
            session['token'] = token
            session['email'] = company.name
            session['role'] = company.role
            
            flash('Logged in successfully', 'success')
            return redirect(url_for('show_events'))

    flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
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
        return redirect(url_for('login_page'))
    except Exception as e:
        db.session.rollback()
        flash('Registration failed. Please try again.', 'danger')
        return render_template('register.html')

@app.route('/events-page')
def show_events():
    events = Event.query.order_by(Event.date).all()
    return render_template('events.html', events=events)

@app.route('/create-event', methods=['GET'])
def create_event_page():
    return render_template('create_event.html')

@app.route('/create-event', methods=['POST'])
def create_event():
    # Get form data
    title = request.form.get('title')
    description = request.form.get('description')
    date = request.form.get('date')
    
    # Validation
    if not title or not description or not date:
        flash('All fields are required.', 'danger')
        return redirect(url_for('create_event_page'))
    
    # For now, we'll need to implement session-based authentication
    # This is a simplified version - you'll need to store JWT tokens in session
    # during login and decode them here
    
    # Parse the date
    try:
        event_date = datetime.datetime.fromisoformat(date)
    except ValueError:
        flash('Invalid date format.', 'danger')
        return redirect(url_for('create_event_page'))
    
    # For demo purposes, assuming we have a way to get the current company
    # In a real implementation, you'd get this from the session token
    company = Company.query.first()  # This is temporary - replace with actual session logic
    
    if not company:
        flash('Company not found.', 'danger')
        return redirect(url_for('create_event_page'))
    
    if not company.approved:
        flash('Company not approved.', 'danger')
        return redirect(url_for('create_event_page'))
    
    # Create the event
    new_event = Event(
        title=title,
        description=description,
        date=event_date,
        company_id=company.id
    )
    
    try:
        db.session.add(new_event)
        db.session.commit()
        flash('Event created successfully!', 'success')
        return redirect(url_for('show_events'))
    except Exception as e:
        db.session.rollback()
        flash('Failed to create event. Please try again.', 'danger')
        return redirect(url_for('create_event_page'))

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))

def decode_token(token):
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return decoded
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)