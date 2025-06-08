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

def require_role(role_to_check): # Renamed arg
    claims = get_jwt()
    user_role = claims.get("role") # Check top-level first
    if user_role is None: # If not top-level, check under a common 'user_claims' key or other potential custom key
        # Flask-JWT-Extended might place it under 'user_claims' or directly if configured.
        # For broad compatibility, check common locations or specific if known.
        # A common newer pattern is for additional_claims to be merged directly.
        # If 'sub' contains an object, it might be in identity.
        # For now, let's assume if not top-level, it might be missing or config is different.
        # The most robust fix without knowing JWT structure is to ensure it's set top-level during creation.
        # However, per subtask, let's try to make require_role flexible.
        # A common alternative key for custom claims is 'user_claims' or directly if JWT_CLAIMS_IN_REFRESH_TOKEN=False etc.
        # Let's assume for now that if it's not top-level, it might be missing.
        # The provided solution was: claims.get("user_claims", {}).get("role")
        # This implies 'user_claims' is a dictionary if it exists.
        user_claims = claims.get("user_claims", {})
        if isinstance(user_claims, dict): # Ensure it's a dict before .get()
             user_role = user_claims.get("role")

    if user_role != role_to_check:
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
        "title": e.title, # Use 'title' as the key, directly from model attribute
        "description": e.description,
        "date": e.date.isoformat(),
        "company_id": e.company_id
    } for e in evts]), 200

@evt_bp.route("/<evt_id>/rsvp", methods=["POST"])
@jwt_required()
def rsvp(evt_id):
    event = Event.query.get_or_404(evt_id) # Fetch event once at the beginning
    require_role("user")
    user_id = get_jwt_identity()

    if RSVP.query.filter_by(event_id=event.id, user_id=user_id).first(): # Use event.id
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
    # We commit RSVP first, then attempt gift card. This means RSVP can succeed even if gift card fails.
    db.session.commit()

    gift_card_message = "and no gift card was offered for this event." # Default message

    # Use the 'event' object fetched at the beginning
    if event.gift_card_amount_cents and event.gift_card_amount_cents > 0:
        amount_to_charge = event.gift_card_amount_cents
        # Stripe integration for gift card
        try:
            stripe.api_key = app.config.get("STRIPE_SECRET_KEY")
            if not stripe.api_key:
                app.logger.error("Stripe API key is not configured for event gift card.")
                raise stripe.error.AuthenticationError("Stripe not configured on server.")

            charge = stripe.Charge.create(
                amount=amount_to_charge,
                currency="usd",
                source=payment_source, # from validated_data
                description=f"Gift card for RSVP to event {evt_id}"
            )
            gift = GiftCard(
                user_id=user_id,
                event_id=evt_id,
                amount_cents=amount_to_charge,
                stripe_charge_id=charge.id
            )
            db.session.add(gift)
            db.session.commit()
            gift_card_message = f"and a gift card for ${amount_to_charge/100:.2f} was issued."

        except stripe.error.StripeError as e:
            app.logger.error(f"Stripe error during RSVP gift card for event {evt_id}, user {user_id}: {str(e)}")
            gift_card_message = f"but failed to process gift card: {str(e)}"
        except Exception as e:
            app.logger.error(f"Unexpected error during gift card processing for event {evt_id}, user {user_id}: {str(e)}")
            gift_card_message = "but an unexpected error occurred with the gift card processing."
    else: # gift_card_amount_cents is None, 0, or invalid
        # gift_card_message remains "and no gift card was offered for this event."
        pass

    # Notify the company
    from app.email_service import send_email

    # Use 'event' object fetched at the beginning for notification details
    # evt = Event.query.get(evt_id) # No need to re-fetch if 'event' is used consistently
    if not event: # Should not happen due to get_or_404, but as a safeguard
        return jsonify({"error": "Event not found for notification"}), 404 # Should be caught by get_or_404

    company = Company.query.get(event.company_id)
    if not company:
        # This case should ideally not happen if data integrity is maintained
        return jsonify({"error": "Company not found for this event"}), 404

    member = User.query.get(user_id)
    if not member: # Should not happen if JWT is valid
        return jsonify({"error": "Member not found"}), 404

    subject = f"New RSVP for your event: {event.name}" # Use event.name
    html = (
        f"<p>{member.email} just RSVPed for <strong>{event.name}</strong> on {event.date}.</p>" # Use event.name
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

        flash_message = 'RSVP successful!'
        if event.gift_card_amount_cents and event.gift_card_amount_cents > 0:
            flash_message += " This event offers a gift card, which could not be processed automatically via this RSVP method."
        flash(flash_message, 'success')

    except Exception as e:
        db.session.rollback()
        if 'UNIQUE constraint failed' in str(e):
            flash('You have already RSVP\'d for this event.', 'warning')
        else:
            flash('Failed to RSVP. Please try again.', 'danger')

    return redirect(url_for('main.show_events'))