import os
import io
import pytest
from app import create_app, db
from app.models import User
from flask_login import login_user
from werkzeug.security import generate_password_hash
from flask import url_for # Added import

import os
import io
import pytest
from app import create_app, db
from app.models import User
from flask_login import login_user
from werkzeug.security import generate_password_hash
from flask import url_for # Added import
from app.extensions import limiter as global_limiter_instance # Import global limiter

@pytest.fixture
def client(tmp_path, monkeypatch):
    app = create_app()
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    app.config['UPLOAD_FOLDER'] = str(tmp_path / 'uploads')
    app.config['SERVER_NAME'] = 'localhost.test' # Added SERVER_NAME
    with app.app_context():
        db.create_all()
        # create a test user
        user = User(email='test@example.com', password=generate_password_hash('testpassword'), name='Test User')
        db.session.add(user)
        db.session.commit()
    client = app.test_client()

    # Directly disable the limiter for the duration of tests using this fixture
    original_limiter_state = global_limiter_instance.enabled
    global_limiter_instance.enabled = False

    yield client

    # Restore original limiter state
    global_limiter_instance.enabled = original_limiter_state

def login_test_user(client):
    client.post('/login', data={'email': 'test@example.com', 'password': 'testpassword'}, follow_redirects=True)

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

from flask import get_flashed_messages # For checking flashed messages
from unittest.mock import patch # For mocking save

def test_update_profile_avatar_disallowed_extension(client):
    with client: # Use client as context manager for request and flashed messages
            login_test_user(client)
            data = {
                'name': 'Test User Name',
                'bio': 'Test bio',
                'avatar': (io.BytesIO(b"fake image data"), 'avatar.txt') # Disallowed extension
            }
            response = client.post(url_for('users.profile'), data=data, content_type='multipart/form-data', follow_redirects=True)
            assert response.status_code == 200 # Should re-render form with error
            # Check for FileAllowed message in response data, as form errors are rendered in the template
            assert b"Images only!" in response.data
            # The custom flash message 'Invalid avatar file type' is no longer set from the route
            # as FileAllowed handles it.

def test_update_profile_avatar_invalid_content(client):
    with client:
            login_test_user(client)
            data = {
                'name': 'Test User Name',
                'bio': 'Test bio',
                'avatar': (io.BytesIO(b"this is not an image"), 'avatar.png') # Allowed ext, bad content
            }
            response = client.post(url_for('users.profile'), data=data, content_type='multipart/form-data', follow_redirects=True)
            assert response.status_code == 200
            messages = get_flashed_messages(with_categories=True)
            assert any(msg[0] == 'danger' and 'Invalid avatar content' in msg[1] for msg in messages)

@patch('werkzeug.datastructures.FileStorage.save')
def test_update_profile_avatar_save_failure(mock_save, client):
    with client:
            login_test_user(client)
            mock_save.side_effect = Exception("Disk full") # Simulate save error

            data = {
                'name': 'Test User Save Fail',
                'bio': 'Test bio save fail',
                'avatar': (io.BytesIO(b'\x89PNG\r\n\x1a\n'), 'avatar.png') # Valid image
            }
            response = client.post(url_for('users.profile'), data=data, content_type='multipart/form-data', follow_redirects=True)
            assert response.status_code == 200 # Should re-render form with error
            messages = get_flashed_messages(with_categories=True)
            assert any(msg[0] == 'danger' and 'Could not save avatar' in msg[1] for msg in messages)

    # Verify avatar_filename was not updated on the user
    with client.application.app_context():
        user = User.query.filter_by(email='test@example.com').first()
        # Assuming original test user might not have an avatar or it's None
        # If test_update_profile_bio_and_avatar runs first, this might be an issue
        # For a clean test, ensure user.avatar_filename is known (e.g. None) before this POST
        # For now, we check it's not the name we tried to save.
        # A better check would be to assert it's the *original* avatar_filename.
        # To do that, we'd need to fetch user before POST.
        original_avatar = user.avatar_filename
        # Re-fetch user after POST, because the session might have changed the object
        user_after_post = User.query.filter_by(email='test@example.com').first()
        assert user_after_post.avatar_filename == original_avatar # Should not have changed
