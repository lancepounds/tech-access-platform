import pytest
from datetime import datetime
from werkzeug.security import generate_password_hash
from flask import url_for

from app import create_app, db
from app.models import Company, User, Event, RSVP

@pytest.fixture
def client():
    app = create_app(config_name='testing')
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SERVER_NAME'] = 'localhost.test'
    with app.app_context():
        db.create_all()
    return app.test_client()

def seed_data(app):
    with app.app_context():
        company = Company(
            name='Acme',
            contact_email='owner@example.com',
            password=generate_password_hash('pw'),
            approved=True,
        )
        db.session.add(company)
        db.session.commit()

        owner = User(email='owner@example.com', password=generate_password_hash('pw'), name='Owner', role='company')
        user1 = User(email='a@example.com', password=generate_password_hash('pw'), name='Alice', role='user')
        user2 = User(email='b@example.com', password=generate_password_hash('pw'), name='Bob', role='user')
        db.session.add_all([owner, user1, user2])
        db.session.commit()

        event = Event(
            id='1',
            title='Export Event',
            description='Desc for export event',
            date=datetime(2030, 1, 1),
            company_id=company.id,
        )
        db.session.add(event)
        db.session.commit()

        r1 = RSVP(user_id=user1.id, event_id=event.id, created_at=datetime(2024, 1, 1, 10, 0))
        r2 = RSVP(user_id=user2.id, event_id=event.id, created_at=datetime(2024, 1, 2, 11, 30))
        db.session.add_all([r1, r2])
        db.session.commit()

        return company.id, owner.id, user1.id, user2.id, event.id

def test_export_attendees_success(client):
    company_id, owner_id, _, _, event_id = seed_data(client.application)

    login_response = client.post('/auth/login', data={'email': 'owner@example.com', 'password': 'pw'}, follow_redirects=False)
    assert login_response.status_code == 302, f"Login POST failed. Status: {login_response.status_code}, Data: {login_response.data.decode()}"

    with client.session_transaction() as sess:
        assert '_user_id' in sess and sess['_user_id'] == str(owner_id)
        assert sess.get('role') == 'company'
        assert sess.get('company_id') == company_id

    with client.application.app_context(): # For url_for
        export_url = url_for('main.export_attendees', event_id=event_id)
    res = client.get(export_url, follow_redirects=True)
    assert res.status_code == 200, f"Export failed. Status: {res.status_code}, Data: {res.data.decode()}"
    assert res.headers['Content-Type'].startswith('text/csv')
    data = res.data.decode('utf-8')
    assert 'Name,Email,RSVP Date' in data
    assert 'Alice' in data and 'Bob' in data

def test_export_attendees_forbidden(client):
    company_id, owner_id, user1_id, _, event_id = seed_data(client.application)

    # Scenario 1: Logged in as a regular user
    login_res_user_a = client.post('/auth/login', data={'email': 'a@example.com', 'password': 'pw'}, follow_redirects=False)
    assert login_res_user_a.status_code == 302
    with client.session_transaction() as sess:
        assert sess.get('role') == 'user'
        assert sess.get('company_id') is None

    with client.application.app_context(): # For url_for
        export_url = url_for('main.export_attendees', event_id=event_id)
    res_user_a = client.get(export_url, follow_redirects=True)
    assert res_user_a.status_code == 403

    client.post('/auth/logout', follow_redirects=True)

    # Scenario 2: Logged in as a representative of a different company
    other_company_email = 'other_owner@example.com'
    other_company = Company(name='OtherCorp', contact_email=other_company_email, password=generate_password_hash('pw'), approved=True)
    other_owner_user = User(email=other_company_email, password=generate_password_hash('pw'), name='Other Rep', role='company')
    with client.application.app_context():
        db.session.add_all([other_company, other_owner_user])
        db.session.commit()
        other_company_id_val = other_company.id

    login_res_other = client.post('/auth/login', data={'email': other_company_email, 'password': 'pw'}, follow_redirects=False)
    assert login_res_other.status_code == 302
    with client.session_transaction() as sess:
        assert sess.get('role') == 'company'
        assert sess.get('company_id') == other_company_id_val

    with client.application.app_context(): # For url_for
        export_url = url_for('main.export_attendees', event_id=event_id)
    res_other = client.get(export_url, follow_redirects=True)
    assert res_other.status_code == 403

    client.post('/auth/logout', follow_redirects=True)

    # Scenario 3: Event not owned by any company
    no_company_event_id = 'event_no_co_id'
    with client.application.app_context():
        no_company_event = Event(id=no_company_event_id, title='No Company Event', description='An event not owned by any company.', date=datetime(2030,1,1), company_id=None)
        db.session.add(no_company_event)
        db.session.commit()

    login_res_owner_again = client.post('/auth/login', data={'email': 'owner@example.com', 'password': 'pw'}, follow_redirects=False)
    assert login_res_owner_again.status_code == 302
    with client.session_transaction() as sess:
        assert sess.get('role') == 'company'
        assert sess.get('company_id') == company_id

    with client.application.app_context(): # For url_for
        export_url_no_co = url_for('main.export_attendees', event_id=no_company_event_id)
    res_no_co = client.get(export_url_no_co, follow_redirects=True)
    assert res_no_co.status_code == 403

    client.post('/auth/logout', follow_redirects=True)

    # Scenario 4: Unauthenticated access
    with client.application.app_context(): # For url_for
        export_url = url_for('main.export_attendees', event_id=event_id)
        login_url_with_next = url_for('auth.login', next=export_url)
    res_unauth = client.get(export_url, follow_redirects=False)
    assert res_unauth.status_code == 302
    assert res_unauth.location == login_url_with_next
