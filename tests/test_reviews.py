import pytest
from app import create_app, db
from datetime import datetime
from app.models import User, Event, Review
from werkzeug.security import generate_password_hash

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False  # Explicitly disable CSRF for these tests
    with app.app_context():
        db.create_all()
        # seed user and event
        user = User(email='u@example.com', password=generate_password_hash('pass'), name='U')
        db.session.add(user)
        db.session.commit()
        event = Event(id='1', title='E', description='D', date=datetime(2025,10,10), company_id=None)
        db.session.add(event)
        db.session.commit()
    client = app.test_client()
    client.post('/login', data={'email':'u@example.com','password':'pass'})
    return client

def test_submit_and_display_review(client):
    # Submit a review
    res1 = client.post('/events/1', data={'rating':'5','comment':'Great!'}, follow_redirects=True)
    assert b'Your review has been posted.' in res1.data
    # Display on detail page
    res2 = client.get('/events/1')
    assert b'5/5' in res2.data
    assert b'Great!' in res2.data


def test_average_rating_calculation(client):
    # Seed multiple reviews
    with client.application.app_context():
        rv1 = Review(user_id=1, event_id=1, rating=4)
        rv2 = Review(user_id=1, event_id=1, rating=2)
        db.session.add_all([rv1, rv2])
        db.session.commit()
    res = client.get('/events/1')
    # (4+2)/2 = 3.0
    assert b'3.0 / 5' in res.data
