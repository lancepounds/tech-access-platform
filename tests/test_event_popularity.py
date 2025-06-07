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


def test_event_popularity_zero(client):
    with client.application.app_context():
        event = Event(id='pop0', title='None', description='desc', date=datetime(2030, 1, 1))
        db.session.add(event)
        db.session.commit()
        url = f'/events/{event.id}'
    res = client.get(url)
    assert res.status_code == 200
    html = res.data.decode('utf-8')
    assert 'RSVPs:</strong> 0' in html


def test_event_popularity_many(client):
    with client.application.app_context():
        user1 = User(email='u1@example.com', password='pw')
        user2 = User(email='u2@example.com', password='pw')
        user3 = User(email='u3@example.com', password='pw')
        event = Event(id='popN', title='Many', description='desc', date=datetime(2030, 1, 1))
        db.session.add_all([user1, user2, user3, event])
        db.session.commit()
        db.session.add_all([
            RSVP(user_id=user1.id, event_id=event.id),
            RSVP(user_id=user2.id, event_id=event.id),
            RSVP(user_id=user3.id, event_id=event.id)
        ])
        db.session.commit()
        url = f'/events/{event.id}'
    res = client.get(url)
    assert res.status_code == 200
    html = res.data.decode('utf-8')
    assert 'RSVPs:</strong> 3' in html

