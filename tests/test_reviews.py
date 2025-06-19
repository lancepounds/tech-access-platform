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
        # Get the user created in the fixture
        user = User.query.filter_by(email='u@example.com').first()
        assert user is not None

        # Event ID is '1' as per fixture for the event
        event_id_from_fixture = '1'

        # Create reviews using the actual user.id (string UUID)
        rv1 = Review(user_id=user.id, event_id=event_id_from_fixture, rating=4, comment="Good")
        rv2 = Review(user_id=user.id, event_id=event_id_from_fixture, rating=2, comment="Okay")

        # Need to create a new user for a third review if reviews must be unique per user/event
        # or ensure test_submit_and_display_review's review doesn't interfere.
        # For this test, let's assume we only have these two reviews for calculation.
        # If the `test_submit_and_display_review` runs first, it adds one review.
        # To isolate, we could delete existing reviews for this event or use a different event.
        # For simplicity, let's assume a clean state for this event's reviews for this test's purpose.
        Review.query.filter_by(event_id=event_id_from_fixture).delete() # Clear previous reviews for this event for this test
        db.session.commit()

        db.session.add_all([rv1, rv2])
        db.session.commit()

    res = client.get(f'/events/{event_id_from_fixture}')
    # Average of 4 and 2 is 3.0.
    # The existing test_submit_and_display_review adds a review with rating 5.
    # If that runs first, average would be (5+4+2)/3 = 11/3 = 3.66... -> "3.7 / 5"
    # By clearing reviews above, we ensure calculation is (4+2)/2 = 3.0
    assert b'3.0 / 5' in res.data
