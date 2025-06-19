import pytest
from app import create_app, db
from app.models import Company, User # User might be needed if admin login is required for some company actions later
from werkzeug.security import generate_password_hash
from flask import url_for, get_flashed_messages

@pytest.fixture
def client():
    app = create_app()
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False, # Disable CSRF for simpler test POSTs
        SECRET_KEY='test_secret_key', # For session/flash messages
        SERVER_NAME='localhost.test' # For url_for
    )
    with app.app_context():
        db.create_all()
    yield app.test_client()

def test_company_registration_page_load(client):
    with client.application.app_context():
        response = client.get(url_for('companies.show_register'))
    assert response.status_code == 200
    assert b"Register Your Company" in response.data

def test_company_registration_success(client):
    with client: # Use client as context manager for request and flashed messages
        # The url_for call below will execute within the context provided by 'with client:'
        data = {
            'company_name': 'TestCo',
                'contact_email': 'contact@testco.com',
                'password': 'password123',
                'confirm_password': 'password123',
                'contact_name': 'Test User',
                'company_description': 'A test company.',
                'products_services': 'Testing services',
                'terms_agreement': 'y', # Added terms_agreement
                # Add other required fields from form if any, or ensure they have defaults/Optional
            }
        with client.application.app_context(): # Add explicit app context for url_for
            target_url = url_for('companies.register_company')
        response = client.post(target_url, data=data, follow_redirects=True)
        assert response.status_code == 200 # Should redirect to login page
        assert b"Company registration submitted successfully!" in response.data # Check for flash message
    with client.application.app_context():
        assert Company.query.filter_by(name='TestCo').first() is not None

def test_company_registration_duplicate_email(client):
    with client.application.app_context():
        # Pre-register a company
        existing_company = Company(
            name='Existing Corp',
            contact_email='duplicate@example.com',
            password=generate_password_hash('securepass'),
                description='An existing company for testing duplicates.', # Changed to 'description'
            contact_name='Some Contact',
            approved=True
        )
        db.session.add(existing_company)
        db.session.commit()

    with client:
        # The url_for call below will execute within the context provided by 'with client:'
        data = {
            'company_name': 'New Corp Name',
                'contact_email': 'duplicate@example.com', # Duplicate email
                'password': 'password123',
                'confirm_password': 'password123',
                'contact_name': 'New Contact',
                'company_description': 'Another test company.',
                'products_services': 'Testing services',
                'terms_agreement': 'y' # Add terms_agreement to pass initial validation
            }
        with client.application.app_context():
            target_url = url_for('companies.register_company')
        response = client.post(target_url, data=data, follow_redirects=True)
        assert response.status_code == 200 # Should re-render form with error
        assert b"Company name or email already exists." in response.data # Check for flash message

def test_company_registration_missing_required_field(client):
    with client:
        data = {
            'company_name': '', # Missing company name
            'contact_email': 'contact@incomplete.com',
            'password': 'password123',
            'confirm_password': 'password123',
            'contact_name': 'Test User',
            'company_description': 'A test company.',
            'products_services': 'Testing services'
        }
        with client.application.app_context():
            target_url = url_for('companies.register_company')
        response = client.post(target_url, data=data, follow_redirects=True)
        assert response.status_code == 200 # Re-renders form
        assert b"This field is required." in response.data # Default WTForms error for DataRequired

def test_company_registration_password_mismatch(client):
    with client:
        data = {
            'company_name': 'Mismatch Co',
            'contact_email': 'mismatch@testco.com',
            'password': 'password123',
            'confirm_password': 'password456', # Mismatched password
            'contact_name': 'Test User',
            'company_description': 'A test company.',
            'products_services': 'Testing services'
        }
        with client.application.app_context():
            target_url = url_for('companies.register_company')
        response = client.post(target_url, data=data, follow_redirects=True)
        assert response.status_code == 200 # Re-renders form
        assert b"Passwords must match." in response.data # Error from EqualTo validator

def test_company_registration_no_terms(client):
    with client:
        data = {
            'company_name': 'NoTerms Co',
            'contact_email': 'noterms@testco.com',
            'password': 'password123',
            'confirm_password': 'password123',
            'contact_name': 'Test User',
            'company_description': 'A test company.',
            'products_services': 'Testing services',
            # terms_agreement is missing
        }
        with client.application.app_context():
            target_url = url_for('companies.register_company')
        response = client.post(target_url, data=data, follow_redirects=True)

    assert response.status_code == 200 # Re-renders form
    assert b"You must agree to the terms and conditions." in response.data


def test_company_model_password_hashing(client):
    """Test direct model password hashing."""
    with client.application.app_context():
        company = Company(
            name="Hashing Test Corp",
            contact_email="hash@example.com",
            # No password set initially
        )
        company.set_password("securepassword123")
        db.session.add(company)
        db.session.commit()

        assert company.password is not None
        assert company.password != "securepassword123"
        assert company.check_password("securepassword123")
        assert not company.check_password("wrongpassword")

def test_company_registration_saves_hashed_password_and_json_interests(client):
    """Test that registration route saves hashed password and JSON interests."""
    with client:
        company_data = {
            'company_name': 'SecurePass Co',
            'contact_email': 'secure@testco.com',
            'password': 'aVerySecurePassword!@#',
            'confirm_password': 'aVerySecurePassword!@#',
            'contact_name': 'Security Officer',
            'company_description': 'A company focused on security.',
            'products_services': 'Security products',
            'interests': ['web_accessibility', 'assistive_tech'], # Use valid choices
            'terms_agreement': 'y',
        }
        with client.application.app_context():
            target_url = url_for('companies.register_company')
        response = client.post(target_url, data=company_data, follow_redirects=True)

        assert response.status_code == 200 # Assuming redirect to login
        assert b"Company registration submitted successfully!" in response.data

    # Verify in database
    with client.application.app_context():
        company = Company.query.filter_by(contact_email='secure@testco.com').first()
        assert company is not None
        assert company.name == 'SecurePass Co'
        # Check password (cannot check hash directly, but check_password should work)
        assert company.check_password('aVerySecurePassword!@#')
        assert not company.check_password('wrongPassword')
        # Check interests (should be Python list when accessed from model)
        assert isinstance(company.interests, list)
        assert company.interests == ['web_accessibility', 'assistive_tech']
