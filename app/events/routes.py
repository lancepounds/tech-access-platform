from flask import Blueprint, request, jsonify, abort, current_app as app, render_template, session, flash, redirect, url_for
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from app.models import Event, RSVP, GiftCard, User, Company
from app.extensions import db
from app.auth.decorators import decode_token
from .schemas import EventSchema, RsvpSchema, IssueGiftSchema # Import schemas
from marshmallow import ValidationError # Import ValidationError
import stripe
from datetime import datetime

evt_bp = Blueprint("events", __name__)

def require_role(role):
    if get_jwt().get("role") != role:
        abort(403)

@evt_bp.route("", methods=["POST"])
@jwt_required()
def create_event():
    require_role("company")
    claims = get_jwt()
    company_id = claims.get("company_id")

    if not company_id:
        return jsonify({"error": "Company ID not found in JWT claims"}), 403 # Or 400
    
    request_data = request.get_json()
    if not request_data:
        return jsonify({"error": "No input data provided"}), 400

    try:
        validated_data = EventSchema().load(request_data)
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400

    # Use validated_data:
    # Note: EventSchema uses 'name', model uses 'title'. Adjust if needed or keep Event.name property.
    # EventSchema uses 'date' which is a datetime object after validation.
    evt = Event(
        title=validated_data['name'], # Assuming Event.name property maps to title
        description=validated_data['description'],
        date=validated_data['date'],
        company_id=company_id
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
    require_role("user") # Changed from "member" to "user"
    user_id = get_jwt_identity()
    if RSVP.query.filter_by(event_id=evt_id, user_id=user_id).first():
        return jsonify({"msg":"already RSVPed"}), 400

    request_data = request.get_json()
    if request_data is None: # Explicitly check for None
        return jsonify({"error": "No input data provided or malformed JSON"}), 400

    try:
        # load_data = request_data if request_data is not None else {} # Not needed if check above is for None
        validated_data = RsvpSchema().load(request_data) # Pass request_data directly
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400

    payment_source = validated_data['payment_source'] # Use validated data

    r = RSVP(user_id=user_id, event_id=evt_id)
    db.session.add(r)
    db.session.commit()

    # Stripe integration for gift card
    # payment_source is already validated and available

    try:
        stripe.api_key = app.config.get("STRIPE_SECRET_KEY")
        if not stripe.api_key: # Ensure API key is actually configured
            app.logger.error("Stripe API key is not configured.")
            # Don't expose this to client, but RSVP is done.
            # This implies a server config issue.
            # For now, proceed without gift card if key is missing, but log it.
            raise stripe.error.AuthenticationError("Stripe not configured on server.")


        # Charge the gift card amount (e.g., $10.00 = 1000 cents)
        # TODO: Consider making this amount configurable per event or globally
        charge = stripe.Charge.create(
            amount=1000, # Hardcoded amount
            currency="usd",
            source=payment_source,
            description=f"Gift card for RSVP to event {evt_id}"
        )

        # Record it in the DB
        gift = GiftCard(
            user_id=user_id,
            event_id=evt_id,
            amount_cents=1000, # Hardcoded amount
            stripe_charge_id=charge.id
        )
        db.session.add(gift)
        db.session.commit()
        gift_card_message = "and gift card issued"

    except stripe.error.StripeError as e:
        app.logger.error(f"Stripe error during RSVP for event {evt_id}, user {user_id}: {str(e)}")
        # RSVP is already committed. User gets RSVP but no gift card in this case.
        # Return a specific error for the gift card part.
        # A more complex rollback of RSVP could be implemented if required.
        gift_card_message = f"but failed to process gift card: {str(e)}"
        # Do not return 500 for Stripe errors if RSVP itself is okay.
        # Instead, the main success message will indicate the gift card issue.

    except Exception as e: # Catch other unexpected errors during payment processing
        app.logger.error(f"Unexpected error during gift card processing for event {evt_id}, user {user_id}: {str(e)}")
        gift_card_message = "but an unexpected error occurred with the gift card processing."


    # Notify the company
    from app.email_service import send_email # Changed from app.mail

    # Fetch event and company info
    evt = Event.query.get(evt_id)
    if not evt:
        return jsonify({"error": "Event not found"}), 404

    company = Company.query.get(evt.company_id)
    if not company:
        # This case should ideally not happen if data integrity is maintained
        return jsonify({"error": "Company not found for this event"}), 404

    member = User.query.get(user_id)
    if not member: # Should not happen if JWT is valid
        return jsonify({"error": "Member not found"}), 404

    subject = f"New RSVP for your event: {evt.name}"
    html = (
        f"<p>{member.email} just RSVPed for <strong>{evt.name}</strong> on {evt.date}.</p>"
        "<p>Log in to your dashboard to view details.</p>"
    )
    send_email(company.contact_email, subject, html)

    return jsonify({"msg": f"RSVP confirmed {gift_card_message}"}), 201

@evt_bp.route("/<evt_id>/issue_gift", methods=["POST"])
@jwt_required()
def issue_gift(evt_id):
    require_role("company")

    request_data = request.get_json()
    if not request_data:
        return jsonify({"error": "No input data provided"}), 400

    try:
        validated_data = IssueGiftSchema().load(request_data)
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400

    user_id = validated_data['user_id']
    payment_source = validated_data['payment_source']
    amount_cents = validated_data['amount_cents'] # Will use missing=1000 if not provided

    stripe.api_key = app.config.get("STRIPE_SECRET_KEY")
    charge = stripe.Charge.create(
        amount=amount_cents,
        currency="usd",
        source=payment_source,
        description=f"Manual gift for RSVP to event {evt_id}"
    )

    gift = GiftCard(user_id=user_id, event_id=evt_id, amount_cents=amount_cents, stripe_charge_id=charge.id)
    db.session.add(gift)
    db.session.commit()
    return jsonify({"msg":"Gift card issued","charge_id":charge.id}), 200

# TODO: The UI version of RSVP (`rsvp_event_ui`) does not currently include
# the Stripe gift card logic found in the API version (`rsvp`).
# This is a potential area for future enhancement to ensure feature parity.
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