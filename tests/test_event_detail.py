import pytest
from datetime import datetime
from app import create_app, db
from app.models import Event, User, RSVP


@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.app_context():
        db.create_all()
    return app.test_client()


def test_event_detail_zero_rsvps(client):
    with client.application.app_context():
        event = Event(id='evt1', title='No RSVPs', description='Desc', date=datetime(2030, 1, 1))
        db.session.add(event)
        db.session.commit()
        url = f'/events/{event.id}'
    res = client.get(url)
    assert res.status_code == 200
    assert b'RSVPs: 0' in res.data


def test_event_detail_two_rsvps(client):
    with client.application.app_context():
        user1 = User(email='a@example.com', password='pw')
        user2 = User(email='b@example.com', password='pw')
        event = Event(id='evt2', title='With RSVPs', description='Desc', date=datetime(2030, 1, 1))
        db.session.add_all([user1, user2, event])
        db.session.commit()
        r1 = RSVP(user_id=user1.id, event_id=event.id)
        r2 = RSVP(user_id=user2.id, event_id=event.id)
        db.session.add_all([r1, r2])
        db.session.commit()
        url = f'/events/{event.id}'
    res = client.get(url)
    assert res.status_code == 200
    assert b'RSVPs: 2' in res.data
