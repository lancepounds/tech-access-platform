
from flask import Blueprint, render_template, request, jsonify, session, flash, redirect, url_for, current_app, abort
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from app.models import Event, RSVP, Company, User, Reward, Category
from sqlalchemy import or_
from app.auth.decorators import decode_token
from app.extensions import db
import datetime
import uuid
import os

main_bp = Blueprint('main', __name__)
from app.auth.routes import login as auth_login

@main_bp.route('/login', methods=['GET', 'POST'])
def login_redirect():
    """Handle login via the auth blueprint."""
    return auth_login()

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/_db_health')
def db_health():
    try:
        if not current_app.supabase:
            return {"status": "error", "message": "Supabase not configured"}, 500

        # Test connectivity by querying information schema
        response = current_app.supabase.table("information_schema.tables").select("*").execute()
        return {"status": "ok", "tables_count": len(response.data)}, 200
    except Exception as e:
        return {"status": "error", "message": str(e)}, 500

@main_bp.route('/events-page')
def show_events():
    events = Event.query.order_by(Event.date).all()
    return render_template('events.html', events=events)


@main_bp.route('/events')
def list_events():
    category_id = request.args.get('category_id', type=int)
    if category_id:
        events = Event.query.filter_by(category_id=category_id).order_by(Event.date).all()
    else:
        events = Event.query.order_by(Event.date).all()
    all_categories = Category.query.order_by(Category.name).all()
    return render_template('event_list.html', events=events, all_categories=all_categories)


@main_bp.route('/events/<event_id>')
def event_detail(event_id):
    """Display a single event's details."""
    event = Event.query.get_or_404(event_id)
    count = event.rsvps.count()
    attendees = [rsvp.user for rsvp in event.rsvps.all()]
    return render_template(
        'event_detail.html', event=event, count=count, attendees=attendees
    )

@main_bp.route('/search')
def search():
    """Search events by title or description."""
    q = request.args.get('q', '').strip()
    if q:
        pattern = f"%{q}%"
        events = Event.query.filter(
            or_(Event.title.ilike(pattern), Event.description.ilike(pattern))
        ).order_by(Event.date).all()
    else:
        events = []
    return render_template('search_results.html', query=q, events=events)


@main_bp.route('/search/companies')
def search_companies():
    """Search companies by name or description."""
    q = request.args.get('q', '').strip()
    if q:
        pattern = f"%{q}%"
        companies = Company.query.filter(
            or_(Company.name.ilike(pattern), Company.description.ilike(pattern))
        ).order_by(Company.name).all()
    else:
        companies = []
    return render_template('company_search_results.html', query=q, companies=companies)

@main_bp.route('/testing-opportunities')
def testing_opportunities():
    return render_template('testing_opportunities.html')

@main_bp.route('/create-event', methods=['GET'])
def create_event_page():
    categories = Category.query.order_by(Category.name).all()
    return render_template('create_event.html', categories=categories)

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
            html_content='<h2>Test Successful!</h2><p>Your SendGrid API key is working correctly.</p>'
        )
        if success:
            return jsonify({'msg': f'Test email sent successfully to {to}'}), 200
        else:
            return jsonify({'msg': 'Email failed to send'}), 500
    except Exception as e:
        return jsonify({'error': f'SendGrid error: {str(e)}'}), 500

@main_bp.route('/create-event', methods=['POST'])
@login_required
def create_event():
    if not current_user.company_id:
        return abort(403)

    # Get form data
    title = request.form.get('title')
    description = request.form.get('description')
    date = request.form.get('date')
    category_id_val = request.form.get('category_id')

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

    # Create the event
    new_event = Event(
        title=title,
        description=description,
        date=event_date,
        company_id=current_user.company_id
    )
    if category_id_val:
        try:
            new_event.category_id = int(category_id_val)
        except ValueError:
            pass

    image_file = request.files.get('image')
    if image_file and image_file.filename:
        filename = secure_filename(image_file.filename)
        unique_name = f"{uuid.uuid4().hex}_{filename}"
        upload_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'events')
        os.makedirs(upload_folder, exist_ok=True)
        image_file.save(os.path.join(upload_folder, unique_name))
        setattr(new_event, 'image_filename', unique_name)

    try:
        db.session.add(new_event)
        db.session.commit()
        flash('Event created successfully!', 'success')
        return redirect(url_for('main.show_events'))
    except Exception as e:
        db.session.rollback()
        flash('Failed to create event. Please try again.', 'danger')
        return redirect(url_for('main.create_event_page'))


@main_bp.route('/events/<event_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    event = Event.query.get_or_404(event_id)
    if not current_user.company_id or event.company_id != current_user.company_id:
        return abort(403)
    categories = Category.query.order_by(Category.name).all()

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        date = request.form.get('date')

        if not title or not description or not date:
            flash('All fields are required.', 'danger')
            return redirect(url_for('main.edit_event', event_id=event_id))

        try:
            event.date = datetime.datetime.fromisoformat(date)
        except ValueError:
            flash('Invalid date format.', 'danger')
            return redirect(url_for('main.edit_event', event_id=event_id))

        event.title = title
        event.description = description
        category_id_val = request.form.get('category_id')
        if category_id_val:
            try:
                event.category_id = int(category_id_val)
            except ValueError:
                pass

        image_file = request.files.get('image')
        if image_file and image_file.filename:
            filename = secure_filename(image_file.filename)
            unique_name = f"{uuid.uuid4().hex}_{filename}"
            upload_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'events')
            os.makedirs(upload_folder, exist_ok=True)
            image_file.save(os.path.join(upload_folder, unique_name))
            setattr(event, 'image_filename', unique_name)

        try:
            db.session.commit()
            flash('Event updated successfully!', 'success')
            return redirect(url_for('main.event_detail', event_id=event.id))
        except Exception:
            db.session.rollback()
            flash('Failed to update event. Please try again.', 'danger')

    return render_template('edit_event.html', event=event, categories=categories)

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
    rsvps = RSVP.query.filter_by(user_email=decoded['email']).join(Event).join(Company).all()

    return render_template('my_rsvps.html', rsvps=rsvps)

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
    # Check if company is logged in via session
    if 'token' not in session or 'role' not in session:
        flash('Please log in to view your dashboard.', 'danger')
        return redirect(url_for('auth.login'))

    if session['role'] != 'company':
        flash('Only companies can view the dashboard.', 'danger')
        return redirect(url_for('main.show_events'))

    # Decode token to get company info
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
    # Only companies can issue gifts
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

    rsvps = RSVP.query.filter_by(user_email=decoded['email']).all()
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

    company = Company.query.filter_by(name=decoded['email']).first()
    if not company or not company.approved:
        return jsonify({'error': 'Company not found or not approved'}), 403

    rsvp = RSVP.query.get(rsvp_id)
    if not rsvp:
        return jsonify({'error': 'RSVP not found'}), 404

    event = Event.query.get(rsvp.event_id)
    if event.company_id != company.id:
        return jsonify({'error': 'This RSVP does not belong to one of your events'}), 403

    rsvp.fulfilled = True

    try:
        db.session.commit()
        return jsonify({'message': f'RSVP for {rsvp.user_email} marked as fulfilled'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to update RSVP: {str(e)}'}), 500


@main_bp.route('/companies/<int:company_id>')
def show_company(company_id):
    """Display a company's details."""
    company = Company.query.get_or_404(company_id)
    return f"Company: {company.name}"
