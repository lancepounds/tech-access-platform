
from flask import Blueprint, request, jsonify, abort, current_app as app, render_template
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from app.models import Event, RSVP
from app.extensions import db

evt_bp = Blueprint("events", __name__, url_prefix="/events")

def require_role(role):
    if get_jwt().get("role") != role:
        abort(403)

@evt_bp.route("", methods=["POST"])
@jwt_required()
def create_event():
    require_role("company")
    data = request.get_json() or {}
    evt = Event(
        name=data.get("name"),
        description=data.get("description"),
        date=data.get("date"),          # ISO string parsed by SQLAlchemy
        company_id=get_jwt_identity()
    )
    db.session.add(evt)
    db.session.commit()
    return jsonify({"id": evt.id}), 201

@evt_bp.route("", methods=["GET"])
@jwt_required(optional=True)
def list_events():
    # public listing for members
    evts = Event.query.order_by(Event.date).all()
    return jsonify([{
        "id": e.id,
        "name": e.name,
        "description": e.description,
        "date": e.date.isoformat(),
        "company_id": e.company_id
    } for e in evts]), 200

@evt_bp.route("/<evt_id>/rsvp", methods=["POST"])
@jwt_required()
def rsvp(evt_id):
    require_role("member")
    user_id = get_jwt_identity()
    if RSVP.query.filter_by(event_id=evt_id, user_id=user_id).first():
        return jsonify({"msg":"already RSVPed"}), 400
    r = RSVP(user_id=user_id, event_id=evt_id)
    db.session.add(r)
    db.session.commit()
    return jsonify({"msg":"RSVP confirmed"}), 201
