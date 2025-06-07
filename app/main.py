import io
import csv
from datetime import date
from flask import Blueprint, render_template, Response, abort
from flask_login import login_required, current_user
from app.models import Event
from app.main.routes import main_bp




@main_bp.route('/events/<int:event_id>/export', methods=['GET'])
@login_required
def export_attendees(event_id):
    event = Event.query.get_or_404(event_id)
    if not current_user.company_id or event.company_id != current_user.company_id:
        abort(403)
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['Name', 'Email', 'RSVP Date'])
    for rsvp in event.rsvps:
        writer.writerow([
            rsvp.user.name,
            rsvp.user.email,
            rsvp.created_at.strftime('%Y-%m-%d %H:%M')
        ])
    output = si.getvalue()
    si.close()
    return Response(
        output,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment;filename=attendees_event_{event_id}.csv'}
    )


@main_bp.route('/events')
def events():
    today = date.today()
    upcoming_events = Event.query.filter(Event.date >= today).order_by(Event.date).all()
    past_events = Event.query.filter(Event.date < today).order_by(Event.date.desc()).all()
    return render_template('events.html', upcoming_events=upcoming_events, past_events=past_events)


