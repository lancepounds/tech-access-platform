import pytest
from datetime import datetime
from app import create_app, db
from app.models import User, Event, Favorite
from werkzeug.security import generate_password_hash

@pytest.fixture
def client(tmp_path):
    app = create_app()
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.app_context():
        db.create_all()
        user = User(email='fav@example.com', password=generate_password_hash('pw'))
        event = Event(id='evt1', title='Fav Event', description='Desc', date=datetime(2030,1,1))
        db.session.add_all([user, event])
        db.session.commit()
    client = app.test_client()
    client.post('/login', data={'email':'fav@example.com','password':'pw'})
    return client


def test_add_and_remove_favorite(client):
    res = client.post('/favorite/evt1', follow_redirects=True)
    assert res.status_code == 200
    with client.application.app_context():
        fav = Favorite.query.first()
        assert fav is not None
    res = client.post('/favorite/evt1', follow_redirects=True)
    assert res.status_code == 200
    with client.application.app_context():
        assert Favorite.query.count() == 0


def test_favorites_listing(client):
    client.post('/favorite/evt1', follow_redirects=True)
    res = client.get('/users/favorites')
    assert res.status_code == 200
    assert b'Fav Event' in res.data
