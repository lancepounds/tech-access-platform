import pytest
from datetime import datetime
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.models import Company, User, Event, RSVP
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
        company = Company(
            name='Acme',
            contact_email='acme@example.com',
            password=generate_password_hash('pw'),
            approved=True,
        )
        owner = User(email='owner@example.com', password=generate_password_hash('pw'), name='Owner')
        user1 = User(email='a@example.com', password=generate_password_hash('pw'), name='Alice')
        user2 = User(email='b@example.com', password=generate_password_hash('pw'), name='Bob')
        db.session.add_all([company, owner, user1, user2])
        db.session.commit()
        event = Event(
            id='1',
            title='Export Event',
            description='Desc',
            date=datetime(2030, 1, 1),
            company_id=company.id,
        )
        db.session.add(event)
        db.session.commit()
        r1 = RSVP(
            user_id=user1.id,
            event_id=event.id,
            created_at=datetime(2024, 1, 1, 10, 0),
        )
        r2 = RSVP(
            user_id=user2.id,
            event_id=event.id,
            created_at=datetime(2024, 1, 2, 11, 30),
        )
        db.session.add_all([r1, r2])
        db.session.commit()
        company_id = company.id
        owner_id = owner.id
        user1_id = user1.id
        user2_id = user2.id
        event_id = event.id
    return company_id, owner_id, user1_id, user2_id, event_id


def patch_loader(mapping):
    @login_manager.user_loader
    def load(uid):
        user = User.query.get(uid)
        if user:
            user.company_id = mapping.get(uid)
        return user


def test_export_attendees_success(client):
    company_id, owner_id, user1_id, user2_id, event_id = seed_data(client.application)
    patch_loader({owner_id: company_id})
    client.post('/login', data={'email': 'owner@example.com', 'password': 'pw'})
    res = client.get(f'/events/{event_id}/export')
    assert res.status_code == 200
    assert res.headers['Content-Type'].startswith('text/csv')
    data = res.data.decode('utf-8')
    assert 'Name,Email,RSVP Date' in data
    assert 'Alice' in data and 'Bob' in data


def test_export_attendees_forbidden(client):
    company_id, owner_id, user1_id, user2_id, event_id = seed_data(client.application)
    patch_loader({owner_id: company_id})
    client.post('/login', data={'email': 'a@example.com', 'password': 'pw'})
    res = client.get(f'/events/{event_id}/export')
    assert res.status_code == 403

    other_company = Company(
        name='Other',
        contact_email='other@example.com',
        password=generate_password_hash('pw'),
        approved=True,
    )
    other_owner = User(email='other@example.com', password=generate_password_hash('pw'), name='Other')
    with client.application.app_context():
        db.session.add_all([other_company, other_owner])
        db.session.commit()
        other_owner_id = other_owner.id
        other_company_id = other_company.id
    patch_loader({other_owner_id: other_company_id})
    client.post('/login', data={'email': 'other@example.com', 'password': 'pw'})
    res = client.get(f'/events/{event_id}/export')
    assert res.status_code == 403
