
from flask import Blueprint, request, jsonify, session, render_template, flash, redirect, url_for
from app.models import Event, Company, User, RSVP, Reward
from app.extensions import db
from app.auth.decorators import decode_token
import datetime
import uuid

events_bp = Blueprint('events', __name__)


@events_bp.route('/', methods=['GET', 'POST'])
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
        event_date = datetime.datetime.fromisoformat(data['date'].replace('Z', '+00:00'))
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


@events_bp.route('/<int:event_id>/rsvp', methods=['POST'])
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


@events_bp.route('/<int:event_id>/rsvps', methods=['GET'])
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


@events_bp.route('/<int:event_id>/rsvp-ui', methods=['POST'])
def rsvp_event_ui(event_id):
    # Check if user is logged in via session
    if 'token' not in session or 'role' not in session:
        flash('Please log in to RSVP for events.', 'danger')
        return redirect(url_for('auth.login_page'))
    
    if session['role'] != 'user':
        flash('Only users can RSVP for events.', 'danger')
        return redirect(url_for('main.show_events'))
    
    # Decode token to get user info
    decoded = decode_token(session['token'])
    if not decoded:
        flash('Session expired. Please log in again.', 'danger')
        return redirect(url_for('auth.login_page'))
    
    user = User.query.filter_by(email=decoded['email']).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('main.show_events'))
    
    event = Event.query.get(event_id)
    if not event:
        flash('Event not found.', 'danger')
        return redirect(url_for('main.show_events'))
    
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
    
    return redirect(url_for('main.show_events'))
