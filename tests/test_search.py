import pytest
from app import create_app, db
from app.models import Event
from datetime import datetime


@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.app_context():
        db.create_all()
        event = Event(title='Sample Event', description='This is a test.', date=datetime(2025, 7, 1))
        db.session.add(event)
        db.session.commit()
    yield app.test_client()


def test_search_finds_event(client):
    res = client.get('/search?q=Sample')
    assert res.status_code == 200
    assert b'Sample Event' in res.data


def test_search_no_results(client):
    res = client.get('/search?q=NoMatch')
    assert res.status_code == 200
    assert b'No events found' in res.data
