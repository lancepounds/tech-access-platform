import re
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
        for i in range(1, 26):
            evt = Event(id=str(i), title=f'Event {i}', description='D', date=datetime(2030, 1, i))
            db.session.add(evt)
        db.session.commit()
    return app.test_client()


def extract_titles(html: str):
    return re.findall(r'<h5 class="card-title[^>]*>([^<]+)</h5>', html)


def test_first_page_shows_ten_events(client):
    res = client.get('/events?page=1')
    assert res.status_code == 200
    titles = extract_titles(res.get_data(as_text=True))
    assert len(titles) == 10
    assert 'Event 1' in titles and 'Event 10' in titles


def test_third_page_shows_remaining_events(client):
    res = client.get('/events?page=3')
    html = res.get_data(as_text=True)
    titles = extract_titles(html)
    assert len(titles) == 5
    assert 'Event 25' in titles
    assert '/events?page=2' in html  # Previous enabled


def test_out_of_range_page_returns_empty(client):
    res = client.get('/events?page=999')
    titles = extract_titles(res.get_data(as_text=True))
    assert res.status_code == 200
    assert titles == []
