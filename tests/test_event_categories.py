import pytest
from datetime import datetime
from app import create_app, db
from app.models import Event, Category

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.app_context():
        db.create_all()
    return app.test_client()


def test_events_show_all_categories(client):
    with client.application.app_context():
        music = Category(name='Music')
        tech = Category(name='Tech')
        db.session.add_all([music, tech])
        db.session.commit()
        e1 = Event(id='m1', title='Music Fest', description='A', date=datetime(2030,1,1), category_id=music.id)
        e2 = Event(id='t1', title='Tech Conf', description='B', date=datetime(2030,1,2), category_id=tech.id)
        db.session.add_all([e1, e2])
        db.session.commit()
    res = client.get('/events')
    assert b'Music Fest' in res.data
    assert b'Tech Conf' in res.data


def test_uncategorized_events_show(client):
    with client.application.app_context():
        cat = Category(name='Tech')
        db.session.add(cat)
        db.session.commit()
        e1 = Event(id='u1', title='Uncat', description='A', date=datetime(2030,1,3))
        e2 = Event(id='c1', title='Categorized', description='B', date=datetime(2030,1,4), category_id=cat.id)
        db.session.add_all([e1, e2])
        db.session.commit()
    res = client.get('/events')
    html = res.data.decode('utf-8')
    assert 'Uncat' in html and 'Categorized' in html
