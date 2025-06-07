from flask import Blueprint, jsonify, abort
from app.models import Event
from flask_login import login_required, current_user

api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/events', methods=['GET'])
def list_events():
    events = Event.query.order_by(Event.date).all()
    return jsonify([{
        'id': int(e.id) if isinstance(e.id, str) and e.id.isdigit() else e.id,
        'title': e.title,
        'date': e.date.strftime('%Y-%m-%d'),
        'category': e.category.name if e.category else None,
        'rsvp_count': e.rsvps.count()
    } for e in events])

@api_bp.route('/events/<int:event_id>', methods=['GET'])
def get_event(event_id):
    e = Event.query.get_or_404(event_id)
    return jsonify({
        'id': int(e.id) if isinstance(e.id, str) and e.id.isdigit() else e.id,
        'title': e.title,
        'description': e.description,
        'date': e.date.strftime('%Y-%m-%d'),
        'category': e.category.name if e.category else None,
        'rsvp_count': e.rsvps.count(),
        'attendees': [{'id': r.user.id, 'name': r.user.name} for r in e.rsvps]
    })
