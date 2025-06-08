import pytest
from flask import url_for, session, jsonify # Added jsonify for response checking
from app import create_app, db
from app.models import User, Company
from werkzeug.security import generate_password_hash
import os
import json # For POST data

@pytest.fixture(scope='module')
def test_client_admin(): # Renamed to avoid conflict if other test_client fixtures exist
    """Create a test client for the Flask application."""
    app = create_app()
    # Ensure a unique app instance name for testing if needed, or rely on default
    # app.name = "test_admin_app"
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SECRET_KEY='test_secret_key_admin_companies', # Unique secret key
        SERVER_NAME='localhost.test',
        SQLALCHEMY_DATABASE_URI=os.environ.get("TEST_DATABASE_URL", "sqlite:///:memory:"),
        LOGIN_DISABLED=False
    )

    with app.app_context():
        db.create_all()
        admin_user = User.query.filter_by(email='admin_companies@example.com').first()
        if not admin_user:
            admin_user = User(
                email='admin_companies@example.com',
                password=generate_password_hash('adminpass'),
                is_admin=True,
                role='admin'
            )
            db.session.add(admin_user)

        regular_user = User.query.filter_by(email='user_companies@example.com').first()
        if not regular_user:
            regular_user = User(
                email='user_companies@example.com',
                password=generate_password_hash('userpass'),
                is_admin=False,
                role='user'
            )
            db.session.add(regular_user)
        db.session.commit()

    client = app.test_client()
    yield client

    # Teardown if using a file-based DB for this module specifically
    # with app.app_context():
    #     db.drop_all()


@pytest.fixture(scope='function')
def regular_user_for_companies(test_client_admin): # Ensure it uses the module-specific client
    with test_client_admin.application.app_context():
        return User.query.filter_by(email='user_companies@example.com').first()

@pytest.fixture(scope='function')
def admin_user_for_companies(test_client_admin): # Ensure it uses the module-specific client
    with test_client_admin.application.app_context():
        return User.query.filter_by(email='admin_companies@example.com').first()

@pytest.fixture(scope='function')
def pending_company_instance(test_client_admin): # Renamed for clarity and using specific client
    with test_client_admin.application.app_context():
        # Ensure clean slate for each test function using this
        Company.query.filter_by(name='Pending Test Corp Admin').delete()
        db.session.commit()

        company = Company(
            name='Pending Test Corp Admin',
            contact_email='pending_admin@example.com',
            password=generate_password_hash('companypass'),
            approved=False
        )
        db.session.add(company)
        db.session.commit()
        return company.id # Return ID

@pytest.fixture(scope='function')
def approved_company_instance(test_client_admin):
    with test_client_admin.application.app_context():
        Company.query.filter_by(name='Approved Test Corp Admin').delete()
        db.session.commit()
        company = Company(
            name='Approved Test Corp Admin',
            contact_email='approved_admin@example.com',
            password=generate_password_hash('companypass'),
            approved=True
        )
        db.session.add(company)
        db.session.commit()
        return company.id # Return ID


def login_user_for_test(client, email, password):
    return client.post(url_for('auth.login'), data=dict(
        email=email,
        password=password
    ), follow_redirects=True)

# --- Tests for list_pending_companies ---

def test_list_pending_no_login(test_client_admin):
    """Test /companies/pending without login."""
    with test_client_admin.application.app_context(): # More explicit app context
        response = test_client_admin.get(url_for('companies.list_pending_companies'))
        # Flask-Login redirects to login page by default if not authenticated
        assert response.status_code == 302
        assert '/login' in response.location

def test_list_pending_as_regular_user(test_client_admin, regular_user_for_companies):
    """Test /companies/pending as a non-admin user."""
    with test_client_admin.application.app_context():
        login_user_for_test(test_client_admin, regular_user_for_companies.email, 'userpass')
        response = test_client_admin.get(url_for('companies.list_pending_companies'))
        assert response.status_code == 403
        assert b'Unauthorized. Admin access required.' in response.data

def test_list_pending_as_admin(test_client_admin, admin_user_for_companies, pending_company_instance):
    """Test /companies/pending as an admin user."""
    with test_client_admin.application.app_context():
        login_user_for_test(test_client_admin, admin_user_for_companies.email, 'adminpass')
        company_to_check = Company.query.get(pending_company_instance) # Use ID directly
        response = test_client_admin.get(url_for('companies.list_pending_companies'))
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)
        assert any(c['name'] == company_to_check.name for c in data) # company_to_check is now fetched instance

# --- Tests for approve_company ---

def test_approve_company_no_login(test_client_admin, pending_company_instance): # pending_company_instance is now an ID
    """Test /companies/approve without login."""
    with test_client_admin.application.app_context():
        test_client_admin.post(url_for('auth.logout')) # Explicitly logout
        company_to_approve = Company.query.get(pending_company_instance) # Use ID
        response = test_client_admin.post(url_for('companies.approve_company'),
                                    json={'name': company_to_approve.name})
        assert response.status_code == 302 # Redirects to login
        assert '/login' in response.location

def test_approve_company_as_regular_user(test_client_admin, regular_user_for_companies, pending_company_instance): # pending_company_instance is now an ID
    """Test /companies/approve as a non-admin user."""
    with test_client_admin.application.app_context():
        login_user_for_test(test_client_admin, regular_user_for_companies.email, 'userpass')
        company_to_approve = Company.query.get(pending_company_instance) # Use ID
        response = test_client_admin.post(url_for('companies.approve_company'),
                                    json={'name': company_to_approve.name})
        assert response.status_code == 403
        assert b'Unauthorized. Admin access required.' in response.data
    with test_client_admin.application.app_context(): # db access needs context
        company = Company.query.get(pending_company_instance) # Use ID
        assert not company.approved

def test_approve_company_as_admin_success(test_client_admin, admin_user_for_companies, pending_company_instance): # pending_company_instance is now an ID
    """Test successful company approval by admin."""
    company_id = pending_company_instance # It's already the ID
    with test_client_admin.application.app_context():
        login_user_for_test(test_client_admin, admin_user_for_companies.email, 'adminpass')
        company_to_approve = Company.query.get(company_id)
        response = test_client_admin.post(url_for('companies.approve_company'),
                                    json={'name': company_to_approve.name})
        assert response.status_code == 200
        assert b'Company Pending Test Corp Admin approved' in response.data # Check specific name
    with test_client_admin.application.app_context(): # db access needs context
        company = Company.query.get(company_id)
        assert company.approved

def test_approve_non_existent_company_as_admin(test_client_admin, admin_user_for_companies):
    """Test approving a non-existent company by admin."""
    with test_client_admin.application.app_context():
        login_user_for_test(test_client_admin, admin_user_for_companies.email, 'adminpass')
        response = test_client_admin.post(url_for('companies.approve_company'),
                                    json={'name': 'NonExistentCorp'})
        assert response.status_code == 404
        assert b'Company not found' in response.data

def test_approve_already_approved_company_as_admin(test_client_admin, admin_user_for_companies, approved_company_instance): # approved_company_instance is now an ID
    """Test approving an already approved company by admin."""
    company_id = approved_company_instance # It's already the ID
    with test_client_admin.application.app_context():
        login_user_for_test(test_client_admin, admin_user_for_companies.email, 'adminpass')
        company_to_check = Company.query.get(company_id)
        response = test_client_admin.post(url_for('companies.approve_company'),
                                    json={'name': company_to_check.name})
        assert response.status_code == 200 # Route returns 200
        assert b'Company already approved' in response.data
    # Verify it's still approved (state hasn't changed negatively)
    with test_client_admin.application.app_context(): # db access needs context
        company = Company.query.get(company_id)
        assert company.approved

def test_approve_company_missing_name_as_admin(test_client_admin, admin_user_for_companies):
    """Test /companies/approve with missing company name by admin."""
    with test_client_admin.application.app_context():
        login_user_for_test(test_client_admin, admin_user_for_companies.email, 'adminpass')
        response = test_client_admin.post(url_for('companies.approve_company'), json={})
        assert response.status_code == 400
        data = json.loads(response.data.decode('utf-8')) # Corrected indentation
        assert 'errors' in data
        assert 'name' in data['errors']
        assert "Missing data for required field." in data['errors']['name']
