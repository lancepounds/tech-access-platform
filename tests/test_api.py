import pytest
from datetime import datetime
from app import create_app, db
from app.models import Event

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.app_context():
        db.create_all()
        e1 = Event(id='1', title='E1', description='D1', date=datetime(2025, 1, 1), company_id=None)
        e2 = Event(id='2', title='E2', description='D2', date=datetime(2025, 2, 2), company_id=None)
        db.session.add_all([e1, e2])
        db.session.commit()
    return app.test_client()

def test_list_events(client):
    res = client.get('/api/events')
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)
    assert any(evt['title']=='E1' for evt in data)

def test_get_event(client):
    res = client.get('/api/events/1')
    assert res.status_code == 200
    evt = res.get_json()
    assert evt['id'] == 1
    assert evt['title'] == 'E1'

def test_event_not_found(client):
    res = client.get('/api/events/999')
    assert res.status_code == 404
