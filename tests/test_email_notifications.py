import pytest
from app import create_app, db
from app.models import User, Event
from app.extensions import mail
from datetime import datetime

@pytest.fixture
def client():
    app = create_app()
    app.config.update(
        TESTING=True,
        MAIL_SUPPRESS_SEND=True,
        MAIL_SERVER='localhost',
        MAIL_PORT=8025
    )
    mail.init_app(app)
    app.mail = mail
    with app.app_context():
        db.create_all()
        user = User(email='u@example.com', password='pass', name='U')
        event = Event(id='1', title='E', description='D', date=datetime(2025, 10, 10), company_id=None)
        db.session.add_all([user, event])
        db.session.commit()
    client = app.test_client()
    client.post('/login', data={'email':'u@example.com','password':'pass'})
    return client

def test_rsvp_sends_email(client):
    with client.application.mail.record_messages() as outbox:
        client.post('/events/1/rsvp')
        assert len(outbox) == 1
        assert 'RSVP Confirmation' in outbox[0].subject
        assert 'Thank you for RSVPing' in outbox[0].body

def test_cancel_sends_email(client):
    client.post('/events/1/rsvp')
    with client.application.mail.record_messages() as outbox:
        client.post('/cancel-rsvp/1')
        assert len(outbox) == 1
        assert 'RSVP Cancellation' in outbox[0].subject
        assert 'has been successfully canceled' in outbox[0].body
