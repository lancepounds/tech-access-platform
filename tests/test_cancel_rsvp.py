import pytest
from datetime import datetime
from app import create_app, db
from app.models import User, Event, RSVP


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


def test_cancel_existing_rsvp(client):
    with client.application.app_context():
        user = User(email='cancel@example.com', password='pw')
        event = Event(id='1', title='Delete Event', description='Desc', date=datetime(2030, 1, 1))
        db.session.add_all([user, event])
        db.session.commit()
        rsvp = RSVP(user_id=user.id, event_id=event.id)
        db.session.add(rsvp)
        db.session.commit()
        evt_id = event.id

    login(client, 'cancel@example.com', 'pw')
    res = client.get('/my-rsvps')
    assert b'Delete Event' in res.data

    res = client.post(f'/cancel-rsvp/{evt_id}', follow_redirects=True)
    assert res.status_code == 200
    assert b"You haven\xe2\x80\x99t signed up for any events yet" in res.data


def test_cancel_nonexistent_rsvp(client):
    with client.application.app_context():
        user = User(email='noevent@example.com', password='pw')
        event = Event(id='2', title='Lonely Event', description='Desc', date=datetime(2031, 1, 1))
        db.session.add_all([user, event])
        db.session.commit()
        evt_id = event.id

    login(client, 'noevent@example.com', 'pw')
    res = client.post(f'/cancel-rsvp/{evt_id}', follow_redirects=True)
    assert res.status_code == 200
    assert b"You haven\xe2\x80\x99t signed up for any events yet" in res.data
