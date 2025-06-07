import pytest
from datetime import datetime
from app import create_app, db
from app.models import User, Event, RSVP, Waitlist

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


def logout(client):
    client.post('/auth/logout')


def test_waitlist_promotion(client):
    with client.application.app_context():
        user1 = User(email='wl1@example.com', password='pw')
        user2 = User(email='wl2@example.com', password='pw')
        event = Event(id='50', title='Cap Event', description='Desc', date=datetime(2030,1,1), capacity=1)
        db.session.add_all([user1, user2, event])
        db.session.commit()
        evt_id = event.id

    login(client, 'wl1@example.com', 'pw')
    res = client.post(f'/events/{evt_id}/rsvp', follow_redirects=True)
    assert b'RSVP successful' in res.data
    with client.application.app_context():
        assert RSVP.query.count() == 1
        assert Waitlist.query.count() == 0

    logout(client)
    login(client, 'wl2@example.com', 'pw')
    res = client.post(f'/events/{evt_id}/rsvp', follow_redirects=True)
    assert b'added to the waitlist' in res.data
    with client.application.app_context():
        assert RSVP.query.count() == 1
        assert Waitlist.query.count() == 1

    logout(client)
    login(client, 'wl1@example.com', 'pw')
    res = client.post(f'/cancel-rsvp/{int(evt_id)}', follow_redirects=True)
    assert b'RSVP cancelled.' in res.data
    with client.application.app_context():
        assert RSVP.query.count() == 1
        assert Waitlist.query.count() == 0
        rsvp = RSVP.query.first()
        user = User.query.get(rsvp.user_id)
        assert user.email == 'wl2@example.com'
