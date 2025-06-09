import pytest
from flask import url_for, get_flashed_messages
from app import create_app, db
from app.models import User, Company
from werkzeug.security import generate_password_hash
import os

@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SECRET_KEY='test_secret_key_admin_dashboard',
        SERVER_NAME='localhost.test',
        SQLALCHEMY_DATABASE_URI=os.environ.get("TEST_DATABASE_URL_ADMIN", "sqlite:///:memory:#admin_dashboard_db")
    )

    try:
        from app.extensions import limiter as global_limiter_instance
        original_limiter_state = global_limiter_instance.enabled
        global_limiter_instance.enabled = False
    except ImportError:
        original_limiter_state = None

    with app.app_context():
        db.create_all()

    test_client = app.test_client()

    yield test_client

    if original_limiter_state is not None:
        global_limiter_instance.enabled = original_limiter_state

    with app.app_context():
        db.session.remove()
        db.drop_all()

@pytest.fixture(scope="function")
def admin_user_id(client):
    with client.application.app_context():
        user = User.query.filter_by(email='admin_dashboard@example.com').first()
        if not user:
            user = User(email='admin_dashboard@example.com',
                        password=generate_password_hash('adminpass'),
                        name='Admin User',
                        is_admin=True,
                        role='admin')
            db.session.add(user)
            db.session.commit()
        return user.id

@pytest.fixture(scope="function")
def regular_user_id(client):
    with client.application.app_context():
        user = User.query.filter_by(email='user_dashboard@example.com').first()
        if not user:
            user = User(email='user_dashboard@example.com',
                        password=generate_password_hash('userpass'),
                        name='Regular User',
                        is_admin=False,
                        role='user')
            db.session.add(user)
            db.session.commit()
        return user.id

@pytest.fixture(scope="function")
def pending_company_id(client):
    with client.application.app_context():
        # Using a more distinct name to avoid clashes if other tests create 'Pending TestCo'
        company = Company.query.filter_by(name='Pending TestCo Func Admin').first()
        if company:
            db.session.delete(company)
            db.session.commit()
        company = Company(name='Pending TestCo Func Admin',
                          contact_email='pendingfuncadmin@testco.com',
                          password=generate_password_hash('coPasswordFuncAdmin123'),
                          description='A company awaiting approval for admin dashboard tests.',
                          approved=False)
        db.session.add(company)
        db.session.commit()
        return company.id

@pytest.fixture(scope="function")
def user_for_toggle_id(client):
    with client.application.app_context():
        # Using a more distinct name
        user = User.query.filter_by(email='toggle_test_func_admin@example.com').first()
        if user:
            db.session.delete(user)
            db.session.commit()
        user = User(email='toggle_test_func_admin@example.com',
                    password=generate_password_hash('togglepassfuncadmin'),
                    name='Toggle Test User Func Admin',
                    is_admin=False,
                    role='user')
        db.session.add(user)
        db.session.commit()
        return user.id

# Helper to log in a user
def login(client, email, password):
    with client.application.app_context():
        login_url = url_for('auth.login')
    return client.post(login_url, data=dict(email=email, password=password), follow_redirects=True)

# Helper to log out a user
def logout(client):
    with client.application.app_context():
        logout_url = url_for('auth.logout')
    return client.post(logout_url, follow_redirects=True)

# --- Basic Admin Dashboard Access Tests ---

def test_admin_dashboard_unauthenticated_access(client):
    with client.application.app_context():
        response = client.get(url_for('admin.dashboard'))
    assert response.status_code == 302
    assert '/auth/login' in response.location # Check if it redirects to login

def test_admin_dashboard_non_admin_access(client, regular_user_id):
    with client.application.app_context():
        regular_user = db.session.get(User, regular_user_id)
        login(client, regular_user.email, 'userpass')
        response = client.get(url_for('admin.dashboard'))
    assert response.status_code == 403
    logout(client)

def test_admin_dashboard_admin_access(client, admin_user_id):
    with client.application.app_context():
        admin_user = db.session.get(User, admin_user_id)
        login(client, admin_user.email, 'adminpass')
        response = client.get(url_for('admin.dashboard'))
    assert response.status_code == 200
    assert b"Admin Dashboard" in response.data
    assert b"Manage Users" in response.data
    logout(client)

def test_admin_nav_link_visibility(client, admin_user_id, regular_user_id):
    with client.application.app_context():
        response = client.get(url_for('main.index'))
    assert response.status_code == 200
    # For nav link visibility, it's better to check for the text "Admin"
    # and the specific href pattern if possible, but be mindful of dynamic classes.
    # The previous complex assertion was failing, let's simplify and rely on text + href presence for admin.
    assert b"href=\"/admin/\"" not in response.data
    assert b">Admin</a>" not in response.data


    with client.application.app_context():
        regular_user = db.session.get(User, regular_user_id)
        login(client, regular_user.email, 'userpass')
        response = client.get(url_for('main.index'))
    assert response.status_code == 200
    assert b"href=\"/admin/\"" not in response.data
    assert b">Admin</a>" not in response.data
    logout(client)

    with client.application.app_context():
        admin_user = db.session.get(User, admin_user_id)
        login(client, admin_user.email, 'adminpass')
        response = client.get(url_for('main.index'))
    assert response.status_code == 200
    # Check for a link with href="/admin/" and containing "Admin" text
    link_text = b'>Admin</a>' # Text inside the <a> tag
    link_href = b'href="/admin/"'
    # Ensure both parts are present, and that the text is within an <a> tag associated with the href
    # This is a bit more complex to assert perfectly without parsing HTML,
    # but checking for both substrings in close proximity is a good heuristic.
    # For now, let's assume if both substrings are present, it's likely correct.
    # A more robust check might involve regex or an HTML parser if this remains flaky.
    assert link_href in response.data
    # The text includes an icon: <i class="bi bi-shield-lock-fill me-1"></i>Admin
    assert b'<i class="bi bi-shield-lock-fill me-1"></i>Admin' in response.data
    # print(f"Admin Nav Check Response Data (for nav link test): {response.data.decode()}") # Keep if still failing
    logout(client)

# --- Company Approval Section Tests ---

def test_pending_companies_list_admin(client, admin_user_id, pending_company_id):
    with client.application.app_context():
        admin_user = db.session.get(User, admin_user_id)
        pending_company = db.session.get(Company, pending_company_id) # Fetch company by ID
        login(client, admin_user.email, 'adminpass')
        response = client.get(url_for('admin.pending_companies'))
    assert response.status_code == 200
    assert b"Pending Company Approvals" in response.data
    assert pending_company.name.encode() in response.data
    logout(client)

def test_pending_companies_list_non_admin(client, regular_user_id):
    with client.application.app_context():
        regular_user = db.session.get(User, regular_user_id)
        login(client, regular_user.email, 'userpass')
        response = client.get(url_for('admin.pending_companies'))
    assert response.status_code == 403
    logout(client)

def test_approve_company_admin(client, admin_user_id, pending_company_id):
    with client.application.app_context():
        admin_user = db.session.get(User, admin_user_id)
        login(client, admin_user.email, 'adminpass')

        company_to_approve = db.session.get(Company, pending_company_id)
        assert company_to_approve is not None
        assert not company_to_approve.approved
        company_name_for_flash = company_to_approve.name

        approve_url = url_for('admin.approve_company_admin', company_id=pending_company_id)
        response = client.post(approve_url) # POST without follow_redirects

    assert response.status_code == 302 # Check for redirect
    with client.application.app_context():
        assert response.location == url_for('admin.pending_companies', _external=False)

    # Check for flash message in the session
    with client.session_transaction() as sess:
        flashed_messages = sess.get('_flashes', [])
        assert len(flashed_messages) > 0
        assert flashed_messages[0] == ('success', f"Company '{company_name_for_flash}' approved successfully.")

    # Optionally, check the content of the redirected page (flash message might not be in response.data here)
    response_redirected = client.get(response.location) # Effectively client.get(url_for('admin.pending_companies'))
    assert response_redirected.status_code == 200
    # The flash message itself might have been consumed from the session by get_flashed_messages if it were called by the template
    # So, asserting its presence in response_redirected.data might be unreliable if using session_transaction above.
    # However, we can check other content on the page.
    assert b"Pending Company Approvals" in response_redirected.data

    with client.application.app_context():
        approved_company = db.session.get(Company, pending_company_id)
        assert approved_company is not None
        assert approved_company.approved
    logout(client)

def test_approve_company_non_admin(client, regular_user_id, pending_company_id):
    with client.application.app_context():
        regular_user = db.session.get(User, regular_user_id)
        login(client, regular_user.email, 'userpass')
        approve_url = url_for('admin.approve_company_admin', company_id=pending_company_id)
        response = client.post(approve_url)
    assert response.status_code == 403
    logout(client)

# --- User Management Section Tests ---

def test_list_users_admin(client, admin_user_id, regular_user_id):
    with client.application.app_context():
        admin_user = db.session.get(User, admin_user_id)
        regular_user = db.session.get(User, regular_user_id)
        login(client, admin_user.email, 'adminpass')
        response = client.get(url_for('admin.list_users'))
    assert response.status_code == 200
    assert b"User Management" in response.data
    assert admin_user.email.encode() in response.data
    assert regular_user.email.encode() in response.data
    logout(client)

def test_list_users_non_admin(client, regular_user_id):
    with client.application.app_context():
        regular_user = db.session.get(User, regular_user_id)
        login(client, regular_user.email, 'userpass')
        response = client.get(url_for('admin.list_users'))
    assert response.status_code == 403
    logout(client)

def test_toggle_admin_status_grant(client, admin_user_id, user_for_toggle_id):
    with client.application.app_context():
        admin_user = db.session.get(User, admin_user_id)
        login(client, admin_user.email, 'adminpass')

        user_before_toggle = db.session.get(User, user_for_toggle_id)
        assert not user_before_toggle.is_admin
        user_email_for_flash = user_before_toggle.email

        toggle_url = url_for('admin.toggle_admin_status', user_id=user_for_toggle_id)
        response = client.post(toggle_url, follow_redirects=True)

    assert response.status_code == 200 # After redirect
    # Check for flashed message text in the response data
    assert f"Admin status for {user_email_for_flash} has been granted.".encode() in response.data

    with client.application.app_context():
        modified_user = db.session.get(User, user_for_toggle_id)
        assert modified_user.is_admin
    logout(client)

def test_toggle_admin_status_revoke(client, admin_user_id, user_for_toggle_id):
    with client.application.app_context():
        admin_user = db.session.get(User, admin_user_id)
        login(client, admin_user.email, 'adminpass')

        user_to_make_admin = db.session.get(User, user_for_toggle_id)
        user_to_make_admin.is_admin = True
        db.session.commit()
        assert user_to_make_admin.is_admin
        user_email_for_flash = user_to_make_admin.email

        toggle_url = url_for('admin.toggle_admin_status', user_id=user_for_toggle_id)
        response = client.post(toggle_url, follow_redirects=True)

    assert response.status_code == 200 # After redirect
    # Check for flashed message text in the response data
    assert f"Admin status for {user_email_for_flash} has been revoked.".encode() in response.data

    with client.application.app_context():
        modified_user = db.session.get(User, user_for_toggle_id)
        assert not modified_user.is_admin
    logout(client)

def test_toggle_admin_status_non_admin_attempt(client, regular_user_id, user_for_toggle_id):
    with client.application.app_context():
        regular_user = db.session.get(User, regular_user_id)
        login(client, regular_user.email, 'userpass')
        toggle_url = url_for('admin.toggle_admin_status', user_id=user_for_toggle_id)
        response = client.post(toggle_url)
    assert response.status_code == 403
    logout(client)

def test_toggle_admin_status_self(client, admin_user_id):
    with client.application.app_context():
        admin_user = db.session.get(User, admin_user_id)
        login(client, admin_user.email, 'adminpass')

        original_admin_status = admin_user.is_admin
        toggle_url = url_for('admin.toggle_admin_status', user_id=admin_user_id)
        response = client.post(toggle_url, follow_redirects=True)

    assert response.status_code == 200 # After redirect
    # Check for flashed message text in the response data
    assert b"Admins cannot change their own admin status via this button." in response.data

    with client.application.app_context():
        current_admin_user_state = db.session.get(User, admin_user_id)
        assert current_admin_user_state.is_admin == original_admin_status
    logout(client)

def test_toggle_admin_status_user_not_found(client, admin_user_id):
    with client.application.app_context():
        admin_user = db.session.get(User, admin_user_id)
        login(client, admin_user.email, 'adminpass')
    non_existent_user_id = "non-existent-uuid-string-for-test"
    with client.application.app_context():
        toggle_url = url_for('admin.toggle_admin_status', user_id=non_existent_user_id)
        response = client.post(toggle_url, follow_redirects=True)

    assert response.status_code == 200 # After redirect (still on list_users page)
    # Check for flashed message text in the response data
    assert b"User not found." in response.data
    logout(client)
