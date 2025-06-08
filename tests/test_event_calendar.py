import pytest
from datetime import datetime
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.models import Company, User, Event
from app.extensions import login_manager


@pytest.fixture

def client():
    app = create_app()
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.app_context():
        db.create_all()
    return app.test_client()


def seed_data(app):
    with app.app_context():
        company = Company(name='CalCo', contact_email='cal@example.com', password=generate_password_hash('pass'), approved=True)
        owner = User(email='co@example.com', password=generate_password_hash('pass'), name='Owner')
        other = User(email='other@example.com', password=generate_password_hash('pass'))
        db.session.add_all([company, owner, other])
        db.session.commit()
        event = Event(id='1', title='Cal Event', description='Desc', date=datetime(2025,12,12), company_id=company.id)
        db.session.add(event)
        db.session.commit()
        return company.id, owner.id, other.id, event.id


def patch_loader(mapping):
    @login_manager.user_loader
    def load(uid):
        user = User.query.get(uid)
        if user:
            user.company_id = mapping.get(uid)
        return user


def test_calendar_download_success(client):
    company_id, owner_id, other_id, event_id = seed_data(client.application)
    patch_loader({owner_id: company_id})
    client.post('/login', data={'email': 'co@example.com', 'password': 'pass'})
    res = client.get(f'/events/{event_id}/calendar.ics')
    assert res.status_code == 200
    assert res.headers['Content-Type'] == 'text/calendar'
    body = res.data.decode('utf-8')
    assert body.startswith('BEGIN:VCALENDAR')
    assert 'SUMMARY:Cal Event' in body


def test_calendar_forbidden(client):
    company_id, owner_id, other_id, event_id = seed_data(client.application)
    patch_loader({owner_id: company_id})
    client.post('/login', data={'email': 'other@example.com', 'password': 'pass'})
    res = client.get(f'/events/{event_id}/calendar.ics')
    assert res.status_code == 403
