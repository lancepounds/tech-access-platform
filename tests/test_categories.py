import pytest
from app import create_app, db
from app.models import User, Category
from werkzeug.security import generate_password_hash
from flask import get_flashed_messages, url_for

@pytest.fixture
def client():
    app = create_app()
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False, # Disable CSRF for simpler test POSTs initially
        SECRET_KEY='test_secret_key', # Needed for session/flash messages
        SERVER_NAME='localhost.test' # Add a dummy server name
    )
    with app.app_context():
        db.create_all()
        # Admin user for creating categories
        admin_user = User(email='admin@example.com', password=generate_password_hash('adminpass'), role='admin')
        db.session.add(admin_user)
        db.session.commit()

    client = app.test_client()
    yield client

def login_admin(client):
    with client.application.app_context(): # Add app context here too
        client.post(url_for('auth.login'), data={'email': 'admin@example.com', 'password': 'adminpass'}, follow_redirects=True)

# Test for company registration (re fix)
def test_company_registration_get(client):
    with client.application.app_context(): # Add app context
        response = client.get(url_for('companies.show_register'))
    assert response.status_code == 200 # Just check if the page loads without NameError for re

# Tests for Category Creation
def test_create_category_page_load(client):
    login_admin(client) # login_admin itself needs app context for its url_for
    with client.application.app_context():
        response = client.get(url_for('categories.create_category'))
    assert response.status_code == 200
    assert b"Create New Category" in response.data

def test_create_category_success(client):
    login_admin(client)
    with client.application.app_context():
        response = client.post(url_for('categories.create_category'), data={'name': 'New Category'}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Category created successfully!" in response.data
    with client.application.app_context():
        assert Category.query.filter_by(name='New Category').first() is not None

def test_create_category_duplicate(client):
    login_admin(client)
    with client.application.app_context():
        # Create first category
        client.post(url_for('categories.create_category'), data={'name': 'Duplicate Category'}, follow_redirects=True)
        # Try to create another with the same name
        response = client.post(url_for('categories.create_category'), data={'name': 'Duplicate Category'}, follow_redirects=True)
    assert response.status_code == 200 # Should re-render the form
    assert b"Category already exists." in response.data
    with client.application.app_context():
        assert Category.query.filter_by(name='Duplicate Category').count() == 1

def test_create_category_empty_name(client):
    login_admin(client)
    with client.application.app_context():
        response = client.post(url_for('categories.create_category'), data={'name': ''}, follow_redirects=True)
    assert response.status_code == 200 # Re-renders form
    assert b"This field is required." in response.data # WTForms default error for DataRequired
    with client.application.app_context():
        assert Category.query.filter_by(name='').first() is None

def test_create_category_name_too_long(client):
    login_admin(client)
    long_name = "a" * 81
    with client.application.app_context():
        response = client.post(url_for('categories.create_category'), data={'name': long_name}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Field must be between 1 and 80 characters long." in response.data # WTForms default error for Length
    with client.application.app_context():
        assert Category.query.filter_by(name=long_name).first() is None

def test_create_category_unauthorized_user(client):
    # Login as a regular user (not admin/company)
    with client.application.app_context():
        reg_user = User(email='user@example.com', password=generate_password_hash('userpass'), role='user')
        db.session.add(reg_user)
        db.session.commit()
        # Login also needs app_context for url_for
        client.post(url_for('auth.login'), data={'email': 'user@example.com', 'password': 'userpass'}, follow_redirects=True)

    with client.application.app_context():
        response = client.get(url_for('categories.create_category'))
    assert response.status_code == 403 # Forbidden

    with client.application.app_context():
        response = client.post(url_for('categories.create_category'), data={'name': 'Attempt by User'}, follow_redirects=True)
    assert response.status_code == 403 # Forbidden
