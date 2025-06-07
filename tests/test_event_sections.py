import pytest
from datetime import date, datetime, timedelta
from app import create_app, db
from app.models import Event


@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.app_context():
        db.create_all()
    return app.test_client()


def test_events_split_into_sections(client):
    with client.application.app_context():
        yesterday = date.today() - timedelta(days=1)
        tomorrow = date.today() + timedelta(days=1)
        past_event = Event(id='past', title='Past Event', description='D', date=datetime.combine(yesterday, datetime.min.time()))
        future_event = Event(id='future', title='Future Event', description='D', date=datetime.combine(tomorrow, datetime.min.time()))
        db.session.add_all([past_event, future_event])
        db.session.commit()
    res = client.get('/events')
    html = res.get_data(as_text=True)
    # Extract sections based on headings
    assert 'Upcoming Events' in html and 'Past Events' in html
    upcoming_section = html.split('Upcoming Events', 1)[1].split('Past Events', 1)[0]
    past_section = html.split('Past Events', 1)[1]
    assert 'Future Event' in upcoming_section
    assert 'Future Event' not in past_section
    assert 'Past Event' in past_section
    assert 'Past Event' not in upcoming_section
