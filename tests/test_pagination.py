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
    return re.findall(r'<li class="list-group-item(?: text-muted)?">\s*<a [^>]+>([^<]+)</a>', html)


def test_all_events_displayed(client):
    res = client.get('/events')
    assert res.status_code == 200
    titles = extract_titles(res.get_data(as_text=True))
    assert len(titles) == 25
    assert 'Event 1' in titles and 'Event 25' in titles
