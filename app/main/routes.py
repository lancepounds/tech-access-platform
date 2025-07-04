from flask import Blueprint, render_template, request, jsonify, session, flash, redirect, url_for, current_app, abort, Response
from flask_login import login_required, current_user
import io
import csv
from werkzeug.utils import secure_filename
from app.models import Event, RSVP, Company, User, Reward, Category, Review, Waitlist
from sqlalchemy import or_, func
from sqlalchemy.orm import joinedload
from datetime import date
from app.reviews.forms import ReviewForm
from app.users.forms import WaitlistForm
from app.auth.decorators import decode_token
from app.extensions import db
from flask_mail import Message
from app.extensions import mail
import datetime
import uuid
import os
import logging # Keep for existing logging.error
from app.utils.files import allowed_image_extension, validate_file_content
from .forms import EventForm

main_bp = Blueprint('main', __name__)

from app.auth.routes import login as auth_login

@main_bp.route('/login', methods=['GET', 'POST'])
def login_redirect():
    return auth_login()

@main_bp.route('/')
def index():
    # Fetch upcoming events
    upcoming_events = Event.query.filter(Event.date > datetime.datetime.utcnow()).order_by(Event.date).limit(5).all()

    # Fetch approved companies
    companies = Company.query.filter_by(approved=True).order_by(Company.created_at.desc()).limit(5).all()

    return render_template('index.html', upcoming_events=upcoming_events, companies=companies)

@main_bp.route('/terms-of-service')
def terms_of_service():
    return render_template('terms_of_service.html')

@main_bp.route('/faq')
def faq():
    return render_template('faq.html')

@main_bp.route('/_db_health')
def db_health():
    try:
        if not current_app.supabase:
            return {"status": "error", "message": "Supabase not configured"}, 500
        response = current_app.supabase.table("information_schema.tables").select("*").execute()
        return {"status": "ok", "tables_count": len(response.data)}, 200
    except Exception as e:
        return {"status": "error", "message": str(e)}, 500

@main_bp.route('/events-page')
def show_events():
    events = Event.query.order_by(Event.date).all()
    counts = {e.id: e.rsvps.count() for e in events}
    return render_template('events.html', events=events, counts=counts)

@main_bp.route('/events')
def list_events():
    page = request.args.get('page', 1, type=int)
    per_page = current_app.config.get('EVENTS_PER_PAGE', 10) # Define EVENTS_PER_PAGE in config or use default
    today_date = date.today()

    upcoming_events_pagination = Event.query.filter(Event.date >= today_date)\
        .order_by(Event.date)\
        .paginate(page=page, per_page=per_page, error_out=False)

    # For past events, we might want a separate pagination or decide how to handle it.
    # Let's paginate upcoming events first and decide on past events.
    # For simplicity, let's also paginate past events, perhaps with a different page parameter if needed,
    # or just show the first page of past events, or a link to a separate paginated past events page.
    # For now, let's assume we want to show the *same page number* for past events, which might be confusing.
    # A better UX might be to only paginate upcoming, and have a separate "View all past events" link.
    # Or, paginate them independently.
    # Let's paginate them with the same page number for now and it can be refined.
    # However, it's more common to paginate a single primary list on a page.
    # I will paginate upcoming_events and keep past_events simple (e.g. first few or unpaginated for now)
    # to avoid complex multi-pagination UI on one page, unless specified.

    # Option 1: Paginate only upcoming events
    past_events = Event.query.filter(Event.date < today_date)\
        .order_by(Event.date.desc())\
        .limit(5).all() # Show a few recent past events, not paginated

    return render_template(
        'events.html',
        upcoming_events_pagination=upcoming_events_pagination,
        past_events=past_events # Pass the limited list of past events
    )

@main_bp.route('/events/<event_id>', methods=['GET', 'POST'])
def event_detail(event_id):
    event = Event.query.get_or_404(event_id)
    form = ReviewForm()
    waitlist_form = WaitlistForm()
    if form.validate_on_submit() and current_user.is_authenticated:
        if not Review.query.filter_by(user_id=current_user.id, event_id=event.id).first():
            new_review = Review(
                user_id=current_user.id,
                event_id=event.id,
                rating=int(form.rating.data),
                comment=form.comment.data,
            )
            db.session.add(new_review)
            db.session.commit()
            flash('Your review has been posted.', 'success')
        return redirect(url_for('main.event_detail', event_id=event.id))
    avg_rating = db.session.query(func.avg(Review.rating)).filter_by(event_id=event.id).scalar() or 0
    reviews = Review.query.filter_by(event_id=event.id).options(joinedload(Review.user)).order_by(Review.created_at.desc()).all()
    count = event.rsvps.count() # Get the count once
    # Eager load User for each RSVP to avoid N+1 when accessing rsvp.user in the loop or template
    rsvps_with_users = event.rsvps.options(joinedload(RSVP.user)).all()
    attendees = [rsvp.user for rsvp in rsvps_with_users]
    return render_template(
        'event_detail.html', event=event, count=count, attendees=attendees,
        form=form, waitlist_form=waitlist_form, Waitlist=Waitlist,
        avg_rating=round(avg_rating, 1), reviews=reviews
    )

@main_bp.route('/events/<event_id>/rsvp', methods=['POST'])
@login_required
def rsvp_event(event_id):
    event = Event.query.get_or_404(event_id)
    if RSVP.query.filter_by(user_id=current_user.id, event_id=str(event_id)).first():
        flash('You have already RSVP\'d for this event.', 'warning')
        return redirect(url_for('main.event_detail', event_id=event_id))
    if event.capacity and RSVP.query.filter_by(event_id=str(event_id)).count() >= event.capacity:
        wait = Waitlist(user_id=current_user.id, event_id=str(event_id))
        db.session.add(wait)
        db.session.commit()
        flash('Event is full. You have been added to the waitlist.', 'info')
        return redirect(url_for('main.event_detail', event_id=event_id))

    new_rsvp = RSVP(event_id=str(event_id), user_id=current_user.id)
    db.session.add(new_rsvp)
    db.session.commit()

    msg = Message(subject=f"RSVP Confirmation for {event.title}", recipients=[current_user.email])
    msg.body = render_template('email/rsvp_confirmation.txt', user=current_user, event=event)
    mail.send(msg)

    flash_message = 'RSVP successful! A confirmation email has been sent.'
    if event.gift_card_amount_cents and event.gift_card_amount_cents > 0:
        flash_message += " This event offers a gift card which may need to be processed via API or by contacting the event organizer."
    flash(flash_message, 'success')

    return redirect(url_for('users.my_rsvps'))

@main_bp.route('/search')
def search():
    q = request.args.get('q', '').strip()
    if q:
        pattern = f"%{q}%"
        events = Event.query.filter(or_(Event.title.ilike(pattern), Event.description.ilike(pattern))).order_by(Event.date).all()
    else:
        events = []
    return render_template('search_results.html', query=q, events=events)

@main_bp.route('/search/companies')
def search_companies():
    q = request.args.get('q', '').strip()
    if q:
        pattern = f"%{q}%"
        companies = Company.query.filter(or_(Company.name.ilike(pattern), Company.description.ilike(pattern))).order_by(Company.name).all()
    else:
        companies = []
    return render_template('company_search_results.html', query=q, companies=companies)

@main_bp.route('/testing-opportunities')
def testing_opportunities():
    return render_template('testing_opportunities.html')

@main_bp.route('/create-event', methods=['GET'])
@login_required
def create_event_page():
    company_id_from_session = session.get('company_id')
    if not (current_user.role == 'company' and company_id_from_session):
        flash("You must be logged in as an approved company representative to create events.", "danger")
        return redirect(url_for('auth.login'))
    form = EventForm()
    form.category_id.choices = [('', 'Uncategorized')] + [(c.id, c.name) for c in Category.query.order_by(Category.name).all()]
    return render_template('create_event.html', form=form, categories=form.category_id.choices)

@main_bp.route('/test-sendgrid', methods=['GET'])
def test_sendgrid():
    from app.mail import send_email
    to = request.args.get('email')
    if not to: return jsonify({'error': 'Provide email as ?email=your@email.com'}), 400
    try:
        success = send_email(to=to, subject='SendGrid Test Email', html_content='<h2>Test Successful!</h2><p>Your SendGrid API key is working correctly.</p>')
        if success: return jsonify({'msg': f'Test email sent successfully to {to}'}), 200
        else: return jsonify({'msg': 'Email failed to send'}), 500
    except Exception as e: return jsonify({'error': f'SendGrid error: {str(e)}'}), 500

@main_bp.route('/create-event', methods=['POST'])
@login_required
def create_event():
    company_id_from_session = session.get('company_id')
    if not (current_user.role == 'company' and company_id_from_session):
        flash("You must be logged in as an approved company representative to create events.", "danger")
        return abort(403)

    form = EventForm()
    form.category_id.choices = [(0, 'Uncategorized')] + [(c.id, c.name) for c in Category.query.order_by(Category.name).all()]

    if form.validate_on_submit():
        title = form.title.data
        description = form.description.data
        date_str = form.date.data
        gift_card_amount_val = form.gift_card_amount_cents.data

        try:
            event_date = datetime.datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S')
        except ValueError:
            form.date.errors.append("Invalid date format. Use YYYY-MM-DDTHH:MM:SS.")
            return render_template('create_event.html', form=form)

        category_id_val = form.category_id.data
        image_file = form.image.data

        new_event = Event(
            title=title,
            description=description,
            date=event_date,
            company_id=company_id_from_session,
            gift_card_amount_cents=gift_card_amount_val
        )
        if category_id_val != 0: new_event.category_id = category_id_val
        else: new_event.category_id = None

        if image_file and image_file.filename:
            if not validate_file_content(image_file):
                form.image.errors.append("Invalid image content. File does not appear to be a valid image.")
                return render_template('create_event.html', form=form)
            else:
                filename = secure_filename(image_file.filename)
                unique_name = f"{uuid.uuid4().hex}_{filename}"
                upload_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'events')
                os.makedirs(upload_folder, exist_ok=True)
                try:
                    image_file.save(os.path.join(upload_folder, unique_name))
                    new_event.image_filename = unique_name
                except Exception as e:
                    logging.error(f"Event image save error for new event: {e}")
                    form.image.errors.append('Could not save event image. System error during save.')

        if not form.image.errors:
            try:
                db.session.add(new_event)
                db.session.commit()
                flash('Event created successfully!', 'success')
                return redirect(url_for('main.show_events'))
            except Exception as e:
                db.session.rollback()
                logging.error(f"Error creating event in DB: {e}")
                flash('Failed to create event. Please try again.', 'danger')

    return render_template('create_event.html', form=form)

@main_bp.route('/events/<event_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    event = Event.query.get_or_404(event_id)
    company_id_from_session = session.get('company_id')
    if not (current_user.role == 'company' and company_id_from_session and event.company_id == company_id_from_session):
        flash("You are not authorized to edit this event.", "danger")
        return abort(403)

    if request.method == 'POST':
        form = EventForm(request.form)
    else:
        form = EventForm(obj=event)
        if event.date:
            form.date.data = event.date.strftime('%Y-%m-%dT%H:%M:%S')
        # gift_card_amount_cents is handled by obj=event for IntegerField

    form.category_id.choices = [(0, 'Uncategorized')] + [(c.id, c.name) for c in Category.query.order_by(Category.name).all()]
    if request.method == 'GET' and event.category_id is None:
        form.category_id.data = 0

    if form.validate_on_submit():
        event.title = form.title.data
        event.description = form.description.data
        date_str = form.date.data
        event.gift_card_amount_cents = form.gift_card_amount_cents.data

        try:
            event_date = datetime.datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S')
        except ValueError:
            form.date.errors.append("Invalid date format. Use YYYY-MM-DDTHH:MM:SS.")
            return render_template('edit_event.html', form=form, event=event)

        event.date = event_date
        event.category_id = form.category_id.data if form.category_id.data != 0 else None

        image_file = form.image.data
        if image_file and image_file.filename:
            if not validate_file_content(image_file):
                form.image.errors.append("Invalid image content. File does not appear to be a valid image.")
                return render_template('edit_event.html', form=form, event=event)
            else:
                filename = secure_filename(image_file.filename)
                unique_name = f"{uuid.uuid4().hex}_{filename}"
                upload_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'events')
                os.makedirs(upload_folder, exist_ok=True)
                try:
                    image_file.save(os.path.join(upload_folder, unique_name))
                    event.image_filename = unique_name
                except Exception as e:
                    logging.error(f"Event image save error for event {event_id}: {e}")
                    form.image.errors.append('Could not save event image. System error during save.')

        if not form.image.errors:
            try:
                db.session.commit()
                flash('Event updated successfully!', 'success')
                return redirect(url_for('main.event_detail', event_id=event.id))
            except Exception as e:
                db.session.rollback()
                logging.error(f"Error updating event {event_id} in DB: {e}")
                flash('Failed to update event. Please try again.', 'danger')

    return render_template('edit_event.html', form=form, event=event)

@main_bp.route('/my-rsvps-page')
def show_my_rsvps():
    if 'token' not in session or 'role' not in session:
        flash('Please log in to view your RSVPs.', 'danger')
        return redirect(url_for('auth.login'))
    if session['role'] != 'user':
        flash('Only users can view RSVPs.', 'danger')
        return redirect(url_for('main.show_events'))
    decoded = decode_token(session['token'])
    if not decoded or 'email' not in decoded:
        flash('Session expired or invalid. Please log in again.', 'danger')
        return redirect(url_for('auth.login')) # Make sure this is the correct login URL

    current_user_obj = User.query.filter_by(email=decoded['email']).first()
    if not current_user_obj:
        flash('User not found. Please log in again.', 'danger')
        return redirect(url_for('auth.login'))

    # Fetch RSVPs with event and event's company
    user_rsvps = RSVP.query.filter_by(user_id=current_user_obj.id)\
        .options(joinedload(RSVP.event).joinedload(Event.company))\
        .order_by(Event.date.desc())\
        .all()

    # Fetch Waitlists with event
    user_waitlists = Waitlist.query.filter_by(user_id=current_user_obj.id)\
        .options(joinedload(Waitlist.event))\
        .join(Event)\
        .order_by(Event.date.desc())\
        .all()

    # For the cancel RSVP form - ensure this form is defined
    # from app.users.forms import CancelRsvpForm # Placeholder, might need to create this form
    # form = CancelRsvpForm()
    # For now, to avoid error if form doesn't exist, we can pass a dummy or None
    # A proper CSRF solution would need a real form or different handling.
    # The template uses form.csrf_token. A FlaskForm passed will have it.
    # Let's assume a simple form can be used or this CSRF is from flask_wtf.html5_validation or similar.
    # For now, I'll mock passing a form object if I can't find CancelRsvpForm.
    # Checking users/forms.py for CancelRsvpForm.
    # It's not there. I will need to create a dummy form or remove the CSRF token for now.
    # Given the scope, I will pass a CSRF token manually if possible, or omit form if it causes issues.
    # The template uses `{{ form.csrf_token }}`. This usually comes from a FlaskForm.
    # Let's check `app/users/forms.py`. It contains `WaitlistForm`. No `CancelRsvpForm`.
    # I will add a dummy form for now for the CSRF token.

    from flask_wtf import FlaskForm # Generic form for CSRF
    class DummyCSRFForm(FlaskForm):
        pass
    form = DummyCSRFForm()

    return render_template('my_rsvps.html', rsvps=user_rsvps, waitlists=user_waitlists, form=form, Waitlist=Waitlist) # Added Waitlist for the template

@main_bp.route('/dashboard')
def company_dashboard():
    if session.get('role') != 'company':
        flash('Please log in as a company.', 'danger')
        return redirect(url_for('auth.login'))
    decoded = decode_token(session['token'])
    company = Company.query.filter_by(name=decoded['email']).first()
    return render_template('company_dashboard.html', events=company.events)

@main_bp.route('/company-dashboard')
def company_dashboard_legacy():
    if 'token' not in session or 'role' not in session:
        flash('Please log in to view your dashboard.', 'danger')
        return redirect(url_for('auth.login'))
    if session['role'] != 'company':
        flash('Only companies can view the dashboard.', 'danger')
        return redirect(url_for('main.show_events'))
    decoded = decode_token(session['token'])
    if not decoded:
        flash('Session expired. Please log in again.', 'danger')
        return redirect(url_for('auth.login'))
    company = Company.query.filter_by(name=decoded['email']).first()
    if not company:
        flash('Company not found.', 'danger')
        return redirect(url_for('main.show_events'))
    if not company.approved:
        flash('Company not approved.', 'danger')
        return redirect(url_for('main.show_events'))
    # Eager load rsvps for each event, and the user for each rsvp
    events = Event.query.filter_by(company_id=company.id)\
        .options(
            selectinload(Event.rsvps).joinedload(RSVP.user)
        ).all()
    return render_template('company_dashboard.html', events=events)

@main_bp.route('/rsvps/<int:rsvp_id>/fulfill-ui', methods=['POST'])
def fulfill_rsvp_ui(rsvp_id):
    if 'token' not in session or 'role' not in session:
        flash('Please log in to fulfill RSVPs.', 'danger')
        return redirect(url_for('auth.login'))
    if session['role'] != 'company':
        flash('Only companies can fulfill RSVPs.', 'danger')
        return redirect(url_for('main.show_events'))
    decoded = decode_token(session['token'])
    if not decoded:
        flash('Session expired. Please log in again.', 'danger')
        return redirect(url_for('auth.login'))
    company = Company.query.filter_by(name=decoded['email']).first()
    if not company or not company.approved:
        flash('Company not found or not approved.', 'danger')
        return redirect(url_for('main.show_events'))
    rsvp = RSVP.query.get(rsvp_id)
    if not rsvp:
        flash('RSVP not found.', 'danger')
        return redirect(url_for('main.company_dashboard'))
    event = Event.query.get(rsvp.event_id)
    if event.company_id != company.id:
        flash('This RSVP does not belong to one of your events.', 'danger')
        return redirect(url_for('main.company_dashboard'))
    if rsvp.fulfilled:
        flash('RSVP is already fulfilled.', 'info')
        return redirect(url_for('main.company_dashboard'))
    rsvp.fulfilled = True
    try:
        db.session.commit()
        flash(f'RSVP for {rsvp.user_email} marked as fulfilled!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Failed to update RSVP. Please try again.', 'danger')
    return redirect(url_for('main.company_dashboard'))

@main_bp.route('/rsvps/<int:rsvp_id>/issue-gift', methods=['POST'])
def issue_gift(rsvp_id):
    if session.get('role') != 'company':
        flash('Please log in as a company.', 'danger')
        return redirect(url_for('auth.login'))
    decoded = decode_token(session['token'])
    company = Company.query.filter_by(name=decoded['email']).first()
    if not company or not company.approved:
        flash('Not authorized.', 'danger')
        return redirect(url_for('auth.login'))
    rsvp = RSVP.query.get_or_404(rsvp_id)
    if rsvp.fulfilled:
        flash('Gift already issued.', 'warning')
        return redirect(url_for('main.company_dashboard'))
    code = str(uuid.uuid4())
    reward = Reward(rsvp_id=rsvp.id, code=code)
    rsvp.fulfilled = True
    db.session.add_all([reward, rsvp])
    db.session.commit()
    flash(f'Gift code issued: {code}', 'success')
    return redirect(url_for('main.company_dashboard'))

@main_bp.route('/my-rsvps', methods=['GET'])
def get_my_rsvps():
    token = request.headers.get('Authorization')
    if not token: return jsonify({'error': 'Missing token'}), 401
    decoded = decode_token(token)
    if not decoded: return jsonify({'error': 'Invalid token'}), 401
    if decoded.get('role') != 'user': return jsonify({'error': 'Unauthorized'}), 403

    user_email = decoded.get('email')
    if not user_email:
        return jsonify({'error': 'User email not in token'}), 401

    user_obj = User.query.filter_by(email=user_email).first()
    if not user_obj:
        return jsonify({'error': 'User not found for token'}), 401

    rsvps = RSVP.query.filter_by(user_id=user_obj.id)\
        .options(
            joinedload(RSVP.event).joinedload(Event.company)
        ).all()

    events_data = []
    for rsvp in rsvps:
        if rsvp.event:
            company_name = None
            if rsvp.event.company: # Company might be nullable on Event if user can create events
                company_name = rsvp.event.company.name
            events_data.append({
                'id': rsvp.event.id,
                'title': rsvp.event.title,
                'description': rsvp.event.description,
                'date': rsvp.event.date.isoformat(),
                'company_name': company_name,
                'rsvp_date': rsvp.created_at.isoformat()
            })
    return jsonify(events_data), 200

@main_bp.route('/rsvps/<int:rsvp_id>/fulfill', methods=['POST'])
def fulfill_rsvp(rsvp_id):
    token = request.headers.get('Authorization')
    if not token: return jsonify({'error': 'Missing token'}), 401
    decoded = decode_token(token)
    if not decoded or decoded['role'] != 'company': return jsonify({'error': 'Unauthorized'}), 403
    company = Company.query.filter_by(name=decoded['email']).first()
    if not company or not company.approved: return jsonify({'error': 'Company not found or not approved'}), 403
    rsvp = RSVP.query.get(rsvp_id)
    if not rsvp: return jsonify({'error': 'RSVP not found'}), 404
    event = Event.query.get(rsvp.event_id)
    if event.company_id != company.id: return jsonify({'error': 'This RSVP does not belong to one of your events'}), 403
    rsvp.fulfilled = True
    try:
        db.session.commit()
        return jsonify({'message': f'RSVP for {rsvp.user_email} marked as fulfilled'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to update RSVP: {str(e)}'}), 500

@main_bp.route('/events/<int:event_id>/rsvp-capacity', methods=['POST'])
@login_required
def rsvp_event_capacity(event_id):
    event = Event.query.get_or_404(event_id)
    if RSVP.query.filter_by(event_id=event.id, user_id=current_user.id).first():
        flash('You have already RSVP\'d for this event.', 'warning')
        return redirect(url_for('main.show_events'))
    if event.capacity is not None and RSVP.query.filter_by(event_id=event.id).count() >= event.capacity:
        wait = Waitlist(user_id=current_user.id, event_id=event.id)
        db.session.add(wait)
        db.session.commit()
        flash('Event is full. You have been added to the waitlist.', 'info')
        return redirect(url_for('main.show_events'))
    rsvp = RSVP(user_id=current_user.id, event_id=event.id)
    db.session.add(rsvp)
    db.session.commit()
    flash('RSVP successful!', 'success')
    return redirect(url_for('main.show_events'))

@main_bp.route('/companies/<int:company_id>')
def show_company(company_id):
    company = Company.query.get_or_404(company_id)
    return f"Company: {company.name}"

@main_bp.route('/events/<string:event_id>/export', methods=['GET']) # Changed to string:event_id
@login_required
def export_attendees(event_id):
    event = Event.query.get_or_404(event_id)

    # Event must be associated with a company for a company to export attendees.
    if not event.company_id:
        # This event is not owned by any company, so no company can export.
        # Or, if events can also be user-owned and users could export, logic would differ.
        # Assuming only companies that own events can export.
        current_app.logger.warning(f"Attempt to export attendees for event {event_id} which has no company_id.")
        abort(403)

    logged_in_company_id = session.get('company_id')

    # User must be acting as a representative of the company that owns the event.
    # This relies on current_user.role being 'company' and session['company_id'] being set correctly at login.
    is_authorized_company_rep = False
    if current_user.is_authenticated and hasattr(current_user, 'role') and current_user.role == 'company':
        if logged_in_company_id is not None and logged_in_company_id == event.company_id:
            is_authorized_company_rep = True

    if not is_authorized_company_rep:
        current_app.logger.warning(
            f"Unauthorized attempt to export attendees for event {event_id}. "
            f"User role: {getattr(current_user, 'role', 'N/A')}, "
            f"Session company_id: {logged_in_company_id}, Event company_id: {event.company_id}"
        )
        abort(403)

    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['Name', 'Email', 'RSVP Date'])
    # Eagerly load the 'user' related to each 'rsvp_item'
    rsvps_with_users = event.rsvps.options(joinedload(RSVP.user)).all()
    for rsvp_item in rsvps_with_users:
        user_name = rsvp_item.user.name if rsvp_item.user else 'N/A'
        user_email = rsvp_item.user.email if rsvp_item.user else 'N/A'
        writer.writerow([
            user_name, user_email,
            rsvp_item.created_at.strftime('%Y-%m-%d %H:%M')
        ])
    output = si.getvalue()
    si.close()
    return Response(output, mimetype='text/csv', headers={'Content-Disposition': f'attachment;filename=attendees_event_{event_id}.csv'})

@main_bp.route('/events/<string:event_id>/calendar.ics', methods=['GET']) # This one should also be string
@login_required
def event_calendar(event_id):
    event = Event.query.get_or_404(event_id)
    if not current_user.company_id or event.company_id != current_user.company_id: abort(403)
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['UID', 'DTSTART', 'SUMMARY', 'DESCRIPTION', 'URL'])
    uid = f"event-{event.id}@{request.host}"
    dtstart = event.date.strftime('%Y%m%d')
    url = url_for('main.event_detail', event_id=event.id, _external=True)
    writer.writerow([uid, dtstart, event.title, event.description, url])
    lines = si.getvalue().splitlines()
    headers = lines[0].split(',')
    values = lines[1].split(',')
    event_lines = '\r\n'.join(f"{h}:{v}" for h, v in zip(headers, values))
    ics_content = (
        'BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//YourApp//EN\r\n' +
        'BEGIN:VEVENT\r\n' + event_lines + '\r\nEND:VEVENT\r\nEND:VCALENDAR'
    )
    return Response(ics_content, headers={'Content-Type': 'text/calendar', 'Content-Disposition': f'attachment; filename=event_{event.id}.ics'})
