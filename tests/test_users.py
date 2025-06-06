import os
import io
import pytest
from app import create_app, db
from app.models import User
from flask_login import login_user

@pytest.fixture
def client(tmp_path, monkeypatch):
    app = create_app()
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['UPLOAD_FOLDER'] = str(tmp_path / 'uploads')
    with app.app_context():
        db.create_all()
        # create a test user
        user = User(email='test@example.com', password='testpassword', name='Test User')
        db.session.add(user)
        db.session.commit()
    client = app.test_client()
    yield client

def login_test_user(client):
    client.post('/login', data={'email': 'test@example.com', 'password': 'testpassword'})

def test_get_profile_page(client):
    login_test_user(client)
    res = client.get('/users/profile')
    assert res.status_code == 200
    assert b'My Profile' in res.data
    assert b'Test User' in res.data

def test_update_profile_bio_and_avatar(client, tmp_path):
    login_test_user(client)
    data = {
        'name': 'Updated Name',
        'bio': 'This is my new bio.',
    }
    # create a small dummy image
    img = (io.BytesIO(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'), 'avatar.png')
    data['avatar'] = img
    res = client.post('/users/profile', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert res.status_code == 200
    # Fetch user from DB and check fields updated
    with client.application.app_context():
        user = User.query.filter_by(email='test@example.com').first()
        assert user.name == 'Updated Name'
        assert user.bio == 'This is my new bio.'
        assert user.avatar_filename is not None
        # check file was saved
        avatar_path = os.path.join(client.application.config['UPLOAD_FOLDER'], 'profiles', user.avatar_filename)
        assert os.path.exists(avatar_path)
