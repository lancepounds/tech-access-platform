from flask import Blueprint, request, jsonify, abort, current_app as app, render_template, session, flash, redirect, url_for
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from app.models import Event, RSVP, GiftCard, User
from app.extensions import db
from app.auth.decorators import decode_token
import stripe

evt_bp = Blueprint("events", __name__, url_prefix="/events")

def require_role(role):
    if get_jwt().get("role") != role:
        abort(403)

@evt_bp.route("", methods=["POST"])
@jwt_required()
def create_event():
    require_role("company")
    claims = get_jwt()
    company_email = claims.get("email")
    
    # Find the company user
    company_user = User.query.filter_by(email=company_email, role="company").first()
    if not company_user:
        return jsonify({"error": "Company user not found"}), 404
    
    data = request.get_json() or {}
    evt = Event(
        name=data.get("name"),
        description=data.get("description"),
        date=data.get("date"),
        company_id=company_user.id
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

    data = request.get_json() or {}

    r = RSVP(user_id=user_id, event_id=evt_id)
    db.session.add(r)
    db.session.commit()

    # Stripe integration for gift card
    stripe.api_key = app.config.get("STRIPE_SECRET_KEY")

    # Charge the gift card amount (e.g., $10.00 = 1000 cents)
    charge = stripe.Charge.create(
        amount=1000,
        currency="usd",
        source=data.get("payment_source"),  # or use PaymentIntent flow
        description=f"Gift card for RSVP to event {evt_id}"
    )

    # Record it in the DB
    gift = GiftCard(
        user_id=user_id,
        event_id=evt_id,
        amount_cents=1000,
        stripe_charge_id=charge.id
    )
    db.session.add(gift)
    db.session.commit()

    # Notify the company
    from app.mail import send_email

    # Fetch event and company info
    evt = Event.query.get(evt_id)
    company = User.query.get(evt.company_id)
    member = User.query.get(user_id)
    subject = f"New RSVP for your event: {evt.name}"
    html = (
        f"<p>{member.email} just RSVPed for <strong>{evt.name}</strong> on {evt.date}.</p>"
        "<p>Log in to your dashboard to view details.</p>"
    )
    send_email(company.email, subject, html)

    return jsonify({"msg":"RSVP confirmed and gift card issued"}), 201

@evt_bp.route("/<evt_id>/issue_gift", methods=["POST"])
@jwt_required()
def issue_gift(evt_id):
    require_role("company")
    data = request.get_json() or {}
    user_id = data.get("user_id")
    amount = data.get("amount_cents", 1000)

    stripe.api_key = app.config.get("STRIPE_SECRET_KEY")
    charge = stripe.Charge.create(
        amount=amount,
        currency="usd",
        source=data.get("payment_source"),
        description=f"Manual gift for RSVP to event {evt_id}"
    )

    gift = GiftCard(user_id=user_id, event_id=evt_id, amount_cents=amount, stripe_charge_id=charge.id)
    db.session.add(gift)
    db.session.commit()
    return jsonify({"msg":"Gift card issued","charge_id":charge.id}), 200

@evt_bp.route('/<int:event_id>/rsvp-ui', methods=['POST'])
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
        new_rsvp = RSVP(event_id=event_id, user_id=user.id)
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