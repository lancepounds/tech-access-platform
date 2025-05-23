
from flask import Flask, request, jsonify
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime

def decode_token(token):
    try:
        token = token.replace("Bearer ", "")
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Secret key for JWT (in production, use environment variable)
JWT_SECRET = 'your-secret-key'

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(80), nullable=False, default='user')

class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(80), nullable=False, default='company')
    approved = db.Column(db.Boolean, default=False)
    events = db.relationship('Event', backref='company', lazy=True)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    rsvps = db.relationship('RSVP', backref='event', lazy=True)

class RSVP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    user_email = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    __table_args__ = (db.UniqueConstraint('event_id', 'user_email'),)

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return 'Hello from Flask!'

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing email or password'}), 400

    # Check if it's a user
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password, data['password']):
        token = jwt.encode({
            'email': user.email,
            'role': user.role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, JWT_SECRET, algorithm='HS256')
        return jsonify({'token': token, 'role': 'user'}), 200

    # Check if it's a company
    company = Company.query.filter_by(name=data['email']).first()
    if company:
        # For companies, we use their name as both email and password
        if data['password'] == data['email']:
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
