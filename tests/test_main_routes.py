import pytest
from app import create_app, db
from app.models import User, Company, Event, Category
from werkzeug.security import generate_password_hash
from flask import url_for, get_flashed_messages
import os
import io
from unittest.mock import patch

@pytest.fixture
def client():
    app = create_app()
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SECRET_KEY='test_secret_key',
        SERVER_NAME='localhost.test', # For url_for
        UPLOAD_FOLDER=os.path.join(app.root_path, '..', 'test_uploads') # Use a temporary test upload folder
    )
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    with app.app_context():
        db.create_all()
        # Company and associated User for creating events
        # The User's email must match the Company's contact_email for web login to correctly associate them
        company_contact_email = 'companyrep@example.com'
        company = Company(
            id=1, # Explicitly set ID for association if needed, or let DB assign
            name='Test Corp',
            contact_email=company_contact_email,
            password=generate_password_hash('companypass'), # Company has its own password for API/other auth
            approved=True,
            role='company' # Company model also has a role
        )
        # This user represents the company when logging in via web forms
        company_representative_user = User(
            email=company_contact_email,
            password=generate_password_hash('companypass'),
            role='company' # This User's role is 'company'
        )
        # No need to manually set company_user.company_id; this is handled by session after login

        db.session.add_all([company, company_representative_user])
        db.session.commit()

    client = app.test_client()
    yield client

    # Teardown: remove test_uploads folder
    # import shutil
    # shutil.rmtree(app.config['UPLOAD_FOLDER'], ignore_errors=True)


def login_company_user(client):
    with client.application.app_context():
        # Login via session by POSTing to the login route using the company representative's User credentials
        client.post(url_for('auth.login'), data={
            'email': 'companyrep@example.com', # Use the User's email
            'password': 'companypass'
        }, follow_redirects=True)

# Tests for Event Image Uploads in app/main/routes.py
def test_create_event_disallowed_image_extension(client):
    with client: # Use client as context manager
        login_company_user(client)
        data = {
            'title': 'Event with Bad Image Ext',
            'description': 'Testing disallowed extension',
            'date': '2024-10-10T10:00:00',
                'category_id': '0', # Use '0' for Uncategorized to pass coerce=int
            'image': (io.BytesIO(b"fake image data"), 'event.txt') # Disallowed extension
        }
        # Remove follow_redirects=True to inspect the direct response of the POST
        response = client.post(url_for('main.create_event'), data=data, content_type='multipart/form-data')
        assert response.status_code == 200 # Should re-render the form with errors if validation fails

        # Check if "Images only!" is in the response.
        # This implies that form.validate_on_submit() was False and form.image.errors was populated by FileAllowed.
        assert b"Images only!" in response.data, "The 'Images only!' message from FileAllowed was not found in the direct POST response."

        # Check that the create_event template is rendered (not the events list redirect)
        html_content = response.data.decode('utf-8')
        assert "Create New Event" in html_content # Specific title of create_event.html
        assert 'name="image"' in html_content # Form field should be present
        # Check that the image field is marked invalid
        # This is a simplified check, assuming 'is-invalid' will be near 'name="image"' if it applies to the image field
        assert 'name="image"' in html_content and 'class="form-control is-invalid"' in html_content


def test_create_event_invalid_image_content(client):
    with client: # Use client as context manager
        login_company_user(client)
        data = {
            'title': 'Event with Bad Image Content',
            'description': 'Testing invalid content',
            'date': '2024-10-11T10:00:00',
                'category_id': '0', # Use '0' for Uncategorized
            'image': (io.BytesIO(b"this is not an image, it's text"), 'event.png') # Allowed extension, bad content
        }
        response = client.post(url_for('main.create_event'), data=data, content_type='multipart/form-data', follow_redirects=True)
        assert response.status_code == 200
        html_content = response.data.decode('utf-8')
        # Check that the image input field has the 'is-invalid' class (approximate check)
        assert 'name="image"' in html_content
        assert 'class="form-control is-invalid"' in html_content
        # Check for the error message (raw message in decoded HTML content)
        expected_error_message = "Invalid image content. File does not appear to be a valid image."
        assert expected_error_message in response.data.decode('utf-8')

@patch('os.makedirs') # To simulate cases where makedirs might be fine
@patch('werkzeug.datastructures.FileStorage.save')
def test_create_event_image_save_failure(mock_save, mock_makedirs, client):
    with client: # Use client as context manager
        login_company_user(client)
        mock_save.side_effect = Exception("Failed to save file") # Simulate save error

        data = {
            'title': 'Event with Save Failure',
            'description': 'Testing image save failure',
            'date': '2024-10-12T10:00:00',
                'category_id': '0', # Use '0' for Uncategorized
            'image': (io.BytesIO(b'\x89PNG\r\n\x1a\n'), 'event.png') # Valid image data
        }
        response = client.post(url_for('main.create_event'), data=data, content_type='multipart/form-data', follow_redirects=True)
        assert response.status_code == 200
        html_content = response.data.decode('utf-8')
        # Check that the image input field has the 'is-invalid' class (approximate check)
        assert 'name="image"' in html_content
        assert 'class="form-control is-invalid"' in html_content
        # Check for the error message (raw message in decoded HTML content)
        expected_error_message = "Could not save event image. System error during save."
        assert expected_error_message in response.data.decode('utf-8')

    # Verify that the event was NOT created due to the image save failure populating form.image.errors
    with client.application.app_context():
        event = Event.query.filter_by(title='Event with Save Failure').first()
        assert event is None
