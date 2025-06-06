
import datetime
import uuid

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.auth.decorators import decode_token
from app.extensions import db
from app.models import RSVP, Company, Event, Reward, User # Added User

main_bp = Blueprint('main', __name__)

@main_bp.route('/login', methods=['GET', 'POST'])
def login_redirect():
    """Redirect /login to /auth/login"""
    return redirect(url_for('auth.login'))

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/_db_health')
def db_health():
    try:
        if not current_app.supabase:
            return {"status": "error", "message": "Supabase not configured"}, 500

        # Test connectivity by querying information schema
        response = (
            current_app.supabase.table("information_schema.tables")
            .select("*")
            .execute()
        )
        return {"status": "ok", "tables_count": len(response.data)}, 200
    except Exception as e:
        return {"status": "error", "message": str(e)}, 500

@main_bp.route('/events-page')
def show_events():
    events = Event.query.order_by(Event.date).all()
    return render_template('events.html', events=events)

@main_bp.route('/testing-opportunities')
def testing_opportunities():
    return render_template('testing_opportunities.html')

@main_bp.route('/create-event', methods=['GET'])
def create_event_page():
    return render_template('create_event.html')

@main_bp.route('/test-sendgrid', methods=['GET'])
def test_sendgrid():
    """Test SendGrid API configuration"""
    from app.mail import send_email

    # Get email from query parameter
    to = request.args.get('email')
    if not to:
        return jsonify({'error': 'Provide email as ?email=your@email.com'}), 400

    try:
        success = send_email(
            to=to, 
            subject='SendGrid Test Email', 
            html_content=(
                '<h2>Test Successful!</h2>'
                '<p>Your SendGrid API key is working correctly.</p>'
            )
        )
        if success:
            return jsonify({'msg': f'Test email sent successfully to {to}'}), 200
        else:
            return jsonify({'msg': 'Email failed to send'}), 500
    except Exception as e:
        return jsonify({'error': f'SendGrid error: {str(e)}'}), 500

@main_bp.route('/create-event', methods=['POST'])
def create_event():
    # Get form data
    title = request.form.get('title')
    description = request.form.get('description')
    date = request.form.get('date')

    # Validation
    if not title or not description or not date:
        flash('All fields are required.', 'danger')
        return redirect(url_for('main.create_event_page'))

    # Parse the date
    try:
        event_date = datetime.datetime.fromisoformat(date)
    except ValueError:
        flash('Invalid date format.', 'danger')
        return redirect(url_for('main.create_event_page'))

    # Get company_id from session
    company_id_from_session = session.get('company_id')
    if not company_id_from_session:
        flash('No company is logged in or session expired.', 'danger')
        return redirect(url_for('auth.login')) # Or a more appropriate page

    company = Company.query.get(company_id_from_session)

    if not company:
        flash('Logged-in company not found in database.', 'danger')
        return redirect(url_for('main.create_event_page'))

    if not company.approved:
        flash('Your company account is not yet approved to create events.', 'danger')
        return redirect(url_for('main.create_event_page'))

    # Create the event
    new_event = Event(
        title=title,
        description=description,
        date=event_date,
        company_id=company.id # Use fetched company's ID
    )

    try:
        db.session.add(new_event)
        db.session.commit()
        flash('Event created successfully!', 'success')
        return redirect(url_for('main.show_events'))
    except Exception:
        db.session.rollback()
        flash('Failed to create event. Please try again.', 'danger')
        return redirect(url_for('main.create_event_page'))

@main_bp.route('/my-rsvps-page')
def show_my_rsvps():
    # Check if user is logged in via session
    if 'token' not in session or 'role' not in session:
        flash('Please log in to view your RSVPs.', 'danger')
        return redirect(url_for('auth.login'))

    if session['role'] != 'user':
        flash('Only users can view RSVPs.', 'danger')
        return redirect(url_for('main.show_events'))

    # Decode token to get user info
    decoded = decode_token(session['token'])
    if not decoded:
        flash('Session expired. Please log in again.', 'danger')
        return redirect(url_for('auth.login'))

    # Query RSVPs for the logged-in user
    user = User.query.filter_by(email=decoded['email']).first()
    if not user:
        flash('User not found for your session. Please log in again.', 'danger')
        return redirect(url_for('auth.login'))

    rsvps = (
        RSVP.query.filter_by(user_id=user.id)
        .join(Event)
        .join(Company) # Assuming Event has a 'company' relationship
        .all()
    )

    return render_template('my_rsvps.html', rsvps=rsvps)

@main_bp.route('/dashboard')
def company_dashboard():
    if session.get('role') != 'company':
        flash('Please log in as a company.', 'danger')
        return redirect(url_for('auth.login'))

    company_id = session.get('company_id')
    company = None
    if company_id:
        company = Company.query.get(company_id)

    if not company: # Fallback or if company_id wasn't in session
        decoded = decode_token(session['token'])
        if decoded and decoded.get('email'):
            company = Company.query.filter_by(contact_email=decoded['email']).first()

    if not company:
        flash('Company information not found. Please log in again.', 'danger')
        return redirect(url_for('auth.login'))

    # Assuming company.events relationship exists or is handled by template
    return render_template('company_dashboard.html', events=company.events, company=company)

@main_bp.route('/company-dashboard')
def company_dashboard_legacy():
    # Check if company is logged in via session
    if 'token' not in session or 'role' not in session:
        flash('Please log in to view your dashboard.', 'danger')
        return redirect(url_for('auth.login'))

    if session['role'] != 'company':
        flash('Only companies can view the dashboard.', 'danger')
        return redirect(url_for('main.show_events'))

    # Decode token to get company info
    # Prioritize company_id from session
    company_id = session.get('company_id')
    company = None
    if company_id:
        company = Company.query.get(company_id)

    if not company: # Fallback if company_id not in session or company not found by id
        decoded = decode_token(session['token'])
        if not decoded:
            flash('Session expired. Please log in again.', 'danger')
            return redirect(url_for('auth.login'))
        if decoded.get('email'):
            company = Company.query.filter_by(contact_email=decoded['email']).first()

    if not company:
        flash('Company not found. Please log in again.', 'danger')
        return redirect(url_for('main.show_events'))

    if not company.approved:
        flash('Company not approved.', 'danger')
        return redirect(url_for('main.show_events'))

    # Query events for the logged-in company with their RSVPs
    events = Event.query.filter_by(company_id=company.id).all()

    # Load RSVPs for each event
    for event in events:
        event.rsvps = RSVP.query.filter_by(event_id=event.id).all()

    return render_template('company_dashboard.html', events=events)

@main_bp.route('/rsvps/<int:rsvp_id>/fulfill-ui', methods=['POST'])
def fulfill_rsvp_ui(rsvp_id):
    # Check if company is logged in via session
    if 'token' not in session or 'role' not in session:
        flash('Please log in to fulfill RSVPs.', 'danger')
        return redirect(url_for('auth.login'))

    if session['role'] != 'company':
        flash('Only companies can fulfill RSVPs.', 'danger')
        return redirect(url_for('main.show_events'))

    # Decode token to get company info
    # Prioritize company_id from session
    company_id = session.get('company_id')
    company = None
    if company_id:
        company = Company.query.get(company_id)

    if not company: # Fallback
        decoded = decode_token(session['token'])
        if not decoded:
            flash('Session expired. Please log in again.', 'danger')
            return redirect(url_for('auth.login'))
        if decoded.get('email'):
            company = Company.query.filter_by(contact_email=decoded['email']).first()

    if not company or not company.approved:
        flash('Company not found, not approved, or session invalid. Please log in again.', 'danger')
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
        user = User.query.get(rsvp.user_id)
        user_email_for_message = user.email if user else f"User ID {rsvp.user_id}"
        flash(f'RSVP for {user_email_for_message} marked as fulfilled!', 'success')
    except Exception:
        db.session.rollback()
        flash('Failed to update RSVP. Please try again.', 'danger')

    return redirect(url_for('main.company_dashboard'))

@main_bp.route('/rsvps/<int:rsvp_id>/issue-gift', methods=['POST'])
def issue_gift(rsvp_id):
    # Only companies can issue gifts
    if session.get('role') != 'company':
        flash('Please log in as a company.', 'danger')
        return redirect(url_for('auth.login'))

    decoded = decode_token(session['token']) # Keep this for now, but company_id is better
    company_id = session.get('company_id')
    company = None
    if company_id:
        company = Company.query.get(company_id)

    if not company and decoded and decoded.get('email'): # Fallback
        company = Company.query.filter_by(contact_email=decoded['email']).first()

    if not company or not company.approved:
        flash('Company not found, not approved, or session invalid. Please log in again.', 'danger')
        return redirect(url_for('auth.login'))

    rsvp = RSVP.query.get_or_404(rsvp_id)
    if rsvp.fulfilled:
        flash('Gift already issued.', 'warning')
        return redirect(url_for('main.company_dashboard'))

    # Generate and save gift code
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
    if not token:
        return jsonify({'error': 'Missing token'}), 401

    decoded = decode_token(token)
    if not decoded:
        return jsonify({'error': 'Invalid token'}), 401

    if decoded['role'] != 'user':
        return jsonify({'error': 'Unauthorized'}), 403

    user = User.query.filter_by(email=decoded['email']).first()
    if not user:
        return jsonify({'error': 'User not found for the provided token.'}), 404

    rsvps = RSVP.query.filter_by(user_id=user.id).all()
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

@main_bp.route('/rsvps/<int:rsvp_id>/fulfill', methods=['POST'])
def fulfill_rsvp(rsvp_id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Missing token'}), 401

    decoded = decode_token(token)
    if not decoded or decoded['role'] != 'company':
        return jsonify({'error': 'Unauthorized'}), 403

    company_id_from_token = decoded.get('company_id')
    company = None
    if company_id_from_token:
        company = Company.query.get(company_id_from_token)

    if not company: # Fallback
        company = Company.query.filter_by(contact_email=decoded.get('email')).first()

    if not company or not company.approved:
        return jsonify({'error': 'Company not found, not approved, or token invalid.'}), 403

    rsvp = RSVP.query.get(rsvp_id)
    if not rsvp:
        return jsonify({'error': 'RSVP not found'}), 404

    event = Event.query.get(rsvp.event_id)
    if event.company_id != company.id:
        return jsonify({
            'error': 'This RSVP does not belong to one of your events'
        }), 403

    rsvp.fulfilled = True

    try:
        db.session.commit()
        user = User.query.get(rsvp.user_id)
        user_email_for_message = user.email if user else f"User ID {rsvp.user_id}"
        return jsonify({
            'message': f'RSVP for {user_email_for_message} marked as fulfilled'
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to update RSVP: {str(e)}'}), 500
