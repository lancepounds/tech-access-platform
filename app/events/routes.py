from flask import Blueprint, request, jsonify, abort, current_app as app, session, flash, redirect, url_for
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from app.models import Event, RSVP, GiftCard, User, Company
from app.extensions import db
from app.auth.decorators import decode_token
from .schemas import EventSchema, RsvpSchema, IssueGiftSchema
from marshmallow import ValidationError
import stripe
from datetime import datetime

evt_bp = Blueprint("events", __name__)

def require_role(role):
    claims = get_jwt()
    if claims.get("role") != role:
        abort(403)

@evt_bp.route("", methods=["POST"])
@jwt_required()
def create_event():
    require_role("company")
    company_id = get_jwt_identity()
    data = request.get_json() or {}
    if not data:
        return jsonify({"error": "No input data provided"}), 400

    try:
        validated = EventSchema().load(data)
    except ValidationError as err:
        return jsonify({"errors": err.messages}), 400

    evt = Event(
        title=validated["name"],
        description=validated["description"],
        date=validated["date"],
        company_id=company_id
    )
    db.session.add(evt)
    db.session.commit()
    return jsonify({"id": evt.id}), 201

@evt_bp.route("", methods=["GET"])
@jwt_required(optional=True)
def list_events():
    evts = Event.query.order_by(Event.date).all()
    return jsonify([
        {
            "id": e.id,
            "name": e.title,
            "description": e.description,
            "date": e.date.isoformat(),
            "company_id": e.company_id
        }
        for e in evts
    ]), 200

@evt_bp.route("/<evt_id>/rsvp", methods=["POST"])
@jwt_required()
def rsvp(evt_id):
    require_role("member")
    user_id = get_jwt_identity()
    if RSVP.query.filter_by(event_id=evt_id, user_id=user_id).first():
        return jsonify({"msg": "already RSVPed"}), 400

    data = request.get_json() or {}
    try:
        validated = RsvpSchema().load(data)
    except ValidationError as err:
        return jsonify({"errors": err.messages}), 400

    payment_source = validated.get("payment_source")
    rsvp = RSVP(user_id=user_id, event_id=evt_id)
    db.session.add(rsvp)
    db.session.commit()

    stripe.api_key = app.config.get("STRIPE_SECRET_KEY")
    if stripe.api_key and payment_source:
        try:
            charge = stripe.Charge.create(
                amount=validated.get("amount_cents", 1000),
                currency="usd",
                source=payment_source,
                description=f"Gift card for RSVP to event {evt_id}"
            )
            gift = GiftCard(
                user_id=user_id,
                event_id=evt_id,
                amount_cents=validated.get("amount_cents", 1000),
                stripe_charge_id=charge.id
            )
            db.session.add(gift)
            db.session.commit()
            gift_msg = "and gift card issued"
        except stripe.error.StripeError as e:
            app.logger.error(f"Stripe error issuing gift card: {e}")
            gift_msg = "but gift card issuance failed"
    else:
        gift_msg = "(no gift card issued)"

    # Notify the company
    evt = Event.query.get(evt_id)
    company = Company.query.get(evt.company_id)
    member = User.query.get(user_id)
    subject = f"New RSVP for your event: {evt.title}"
    html = (
        f"<p>{member.email} just RSVPed for <strong>{evt.title}</strong> on {evt.date}.</p>"
        "<p>Log in to your dashboard to view details.</p>"
    )
    from app.email_service import send_email
    send_email(company.contact_email, subject, html)

    return jsonify({"msg": f"RSVP confirmed {gift_msg}"}), 201

@evt_bp.route("/<evt_id>/issue_gift", methods=["POST"])
@jwt_required()
def issue_gift(evt_id):
    require_role("company")
    data = request.get_json() or {}
    try:
        validated = IssueGiftSchema().load(data)
    except ValidationError as err:
        return jsonify({"errors": err.messages}), 400

    stripe.api_key = app.config.get("STRIPE_SECRET_KEY")
    charge = stripe.Charge.create(
        amount=validated.get("amount_cents", 1000),
        currency="usd",
        source=validated["payment_source"],
        description=f"Manual gift for RSVP to event {evt_id}"
    )
    gift = GiftCard(
        user_id=validated["user_id"],
        event_id=evt_id,
        amount_cents=validated.get("amount_cents", 1000),
        stripe_charge_id=charge.id
    )
    db.session.add(gift)
    db.session.commit()
    return jsonify({"msg": "Gift card issued", "charge_id": charge.id}), 200

@evt_bp.route('/<int:event_id>/rsvp-ui', methods=['POST'])
def rsvp_event_ui(event_id):
    if 'token' not in session or 'role' not in session:
        flash('Please log in to RSVP for events.', 'danger')
        return redirect(url_for('auth.login_page'))

    if session['role'] != 'member':
        flash('Only members can RSVP for events.', 'danger')
        return redirect(url_for('main.show_events'))

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
        new_rsvp = RSVP(event_id=event_id, user_id=user.id)
        db.session.add(new_rsvp)
        db.session.commit()
        flash('RSVP successful!', 'success')
    except Exception as e:
        db.session.rollback()
        if 'UNIQUE constraint failed' in str(e):
            flash('You have already RSVPed for this event.', 'warning')
        else:
            flash('Failed to RSVP. Please try again.', 'danger')

    return redirect(url_for('main.show_events'))