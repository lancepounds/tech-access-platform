import pytest
from datetime import datetime
from app import create_app, db
from app.models import User, Event, RSVP
from werkzeug.security import generate_password_hash

@pytest.fixture
def client(tmp_path):
    app = create_app()
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.app_context():
        db.create_all()
    return app.test_client()


def login(client, email, password):
    client.post('/login', data={'email': email, 'password': password})


def test_my_rsvps_shows_event(client):
    with client.application.app_context():
        user = User(email='user1@example.com', password=generate_password_hash('pw'))
        event = Event(id='10', title='Test Event', description='Desc', date=datetime(2025,1,1))
        db.session.add_all([user, event])
        db.session.commit()
        rsvp = RSVP(user_id=user.id, event_id=event.id)
        db.session.add(rsvp)
        db.session.commit()
    login(client, 'user1@example.com', 'pw')
    res = client.get('/my-rsvps')
    assert res.status_code == 200
    assert b'Test Event' in res.data


def test_my_rsvps_empty(client):
    with client.application.app_context():
        user = User(email='user2@example.com', password=generate_password_hash('pw'))
        db.session.add(user)
        db.session.commit()
    login(client, 'user2@example.com', 'pw')
    res = client.get('/my-rsvps')
    assert res.status_code == 200
    assert b"You haven\xe2\x80\x99t signed up for any events yet" in res.data

