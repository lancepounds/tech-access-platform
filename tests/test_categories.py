import pytest
from app import create_app, db
from app.models import User, Category, Event
from werkzeug.security import generate_password_hash
from flask import get_flashed_messages, url_for, session as flask_session # To check session
from datetime import datetime
from app.categories.forms import DeleteCategoryForm # Import DeleteCategoryForm

import pytest
from app import create_app, db
from app.models import User, Category, Event
from werkzeug.security import generate_password_hash
from flask import get_flashed_messages, url_for, session as flask_session # To check session
from datetime import datetime
from app.categories.forms import DeleteCategoryForm # Import DeleteCategoryForm
from app.extensions import limiter as global_limiter_instance # Import global limiter

@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.config.update(
        TESTING=True,
        # RATELIMIT_ENABLED = False is set in app/__init__.py for TESTING=True
        # However, directly disabling the instance can be more robust for decorators
        # that might have captured the limiter instance before app config is fully processed by it.
        WTF_CSRF_ENABLED=False,
        SECRET_KEY='test_secret_key_categories', # Unique key
        SERVER_NAME='localhost.test',
        SQLALCHEMY_DATABASE_URI=os.environ.get("TEST_DATABASE_URL_CATEGORIES", "sqlite:///:memory:") # Unique DB
    )
    with app.app_context():
        db.create_all()
        # Admin user for tests
        admin_user = User.query.filter_by(email='admin_cat@example.com').first()
        if not admin_user:
            admin_user = User(email='admin_cat@example.com', password=generate_password_hash('adminpass'), role='admin', is_admin=True) # Set is_admin=True
            db.session.add(admin_user)

        # Regular user for tests
        regular_user = User.query.filter_by(email='user_cat@example.com').first()
        if not regular_user:
            regular_user = User(email='user_cat@example.com', password=generate_password_hash('userpass'), role='user', is_admin=False)
            db.session.add(regular_user)

        db.session.commit()

    client = app.test_client()

    # Directly disable the limiter for the duration of tests in this module
    original_limiter_state = global_limiter_instance.enabled
    global_limiter_instance.enabled = False

    yield client

    # Restore original limiter state after tests
    global_limiter_instance.enabled = original_limiter_state

    # Teardown: Optional if using in-memory, but good practice for file DBs
    # with app.app_context():
    #     db.drop_all()


def login_user(client, email, password): # Made more generic
    # The calling test should already be within an app context for url_for
    return client.post(url_for('auth.login'), data={'email': email, 'password': password}, follow_redirects=True)

# --- Category Creation Tests (existing, slightly adapted) ---
def test_create_category_page_load_as_admin(client):
    with client.application.app_context():
        login_user(client, 'admin_cat@example.com', 'adminpass')
        response = client.get(url_for('categories.create_category'))
    assert response.status_code == 200
    assert b"Create New Category" in response.data

def test_create_category_success(client):
    category_name = 'New Test Category Success'
    with client.application.app_context():
        login_user(client, 'admin_cat@example.com', 'adminpass')
        # Ensure category doesn't exist from a previous failed run if db is persistent
        existing_cat = Category.query.filter_by(name=category_name).first()
        if existing_cat:
            db.session.delete(existing_cat)
            db.session.commit()
        response = client.post(url_for('categories.create_category'), data={'name': category_name}, follow_redirects=True)
    assert response.status_code == 200 # Redirects to list_categories
    assert b"Category created successfully!" in response.data # Flashed message
    assert b"Categories" in response.data # Check if list_categories page is rendered
    with client.application.app_context():
        assert Category.query.filter_by(name=category_name).first() is not None

def test_create_category_duplicate(client):
    with client.application.app_context():
        login_user(client, 'admin_cat@example.com', 'adminpass')
        # Ensure 'Duplicate Test Category' exists for the test
        cat = Category.query.filter_by(name='Duplicate Test Category').first()
        if not cat:
            cat = Category(name='Duplicate Test Category')
            db.session.add(cat)
            db.session.commit()
        response = client.post(url_for('categories.create_category'), data={'name': 'Duplicate Test Category'}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Category already exists." in response.data

def test_create_category_unauthorized_user(client):
    with client.application.app_context():
        login_user(client, 'user_cat@example.com', 'userpass') # Login as regular user
        response_get = client.get(url_for('categories.create_category'))
        response_post = client.post(url_for('categories.create_category'), data={'name': 'Attempt by User'}, follow_redirects=True)
    assert response_get.status_code == 403
    assert response_post.status_code == 403

# --- Category Listing Tests ---
def test_list_categories_page_load(client):
    with client.application.app_context():
        login_user(client, 'user_cat@example.com', 'userpass') # Any logged in user
        # Ensure a category exists to be listed
        cat = Category.query.filter_by(name='Listable Category').first()
        if not cat:
            cat = Category(name='Listable Category')
            db.session.add(cat)
            db.session.commit()
        response = client.get(url_for('categories.list_categories'))
    assert response.status_code == 200
    assert b"Categories" in response.data
    assert b"Listable Category" in response.data
    assert b"Edit" not in response.data # Regular user should not see Edit

def test_list_categories_as_admin(client):
    with client.application.app_context():
        login_user(client, 'admin_cat@example.com', 'adminpass')
        cat = Category.query.filter_by(name='AdminListable Category').first()
        if not cat:
            cat = Category(name='AdminListable Category')
            db.session.add(cat)
            db.session.commit()
        response = client.get(url_for('categories.list_categories'))
    assert response.status_code == 200
    assert b"AdminListable Category" in response.data
    assert b"Edit" in response.data # Admin should see Edit

# --- Category Editing Tests ---
@pytest.fixture(scope="function")
def category_for_edit(client): # Function scope to ensure it's fresh
    with client.application.app_context():
        Category.query.filter_by(name="CategoryToEdit").delete()
        Category.query.filter_by(name="NewNameToConflict").delete()
        db.session.commit()
        cat = Category(name="CategoryToEdit")
        db.session.add(cat)
        db.session.commit()
        return cat.id # Return ID

def test_edit_category_page_load_as_admin(client, category_for_edit): # category_for_edit is now an ID
    with client.application.app_context():
        login_user(client, 'admin_cat@example.com', 'adminpass')
        category = db.session.get(Category, category_for_edit) # Re-fetch
        assert category is not None # Ensure it was found
        response = client.get(url_for('categories.edit_category', category_id=category.id))
    assert response.status_code == 200
    assert b"Edit Category" in response.data
    assert b"CategoryToEdit" in response.data # Check if current name is in form

def test_edit_category_unauthorized_user(client, category_for_edit): # category_for_edit is now an ID
    with client.application.app_context():
        login_user(client, 'user_cat@example.com', 'userpass')
        # We just need the ID for url_for, no need to fetch if we are only checking auth
        response_get = client.get(url_for('categories.edit_category', category_id=category_for_edit))
        response_post = client.post(url_for('categories.edit_category', category_id=category_for_edit), data={'name': 'AttemptEditByUser'})
    assert response_get.status_code == 403
    assert response_post.status_code == 403

def test_edit_category_success(client, category_for_edit): # category_for_edit is now an ID
    with client.application.app_context():
        login_user(client, 'admin_cat@example.com', 'adminpass')
        edit_url = url_for('categories.edit_category', category_id=category_for_edit)
        list_url_relative = url_for('categories.list_categories', _external=False) # For location check
        list_url_for_get = url_for('categories.list_categories') # For client.get

        response_post = client.post(edit_url, data={'name': 'UpdatedCategoryName'}) # No follow_redirects

        assert response_post.status_code == 302 # Check for redirect
        assert response_post.location == list_url_relative

        # Check for flash message in session BEFORE following redirect
        with client.session_transaction() as sess: # Corrected indentation for this block
            assert '_flashes' in sess
            assert sess['_flashes'][0] == ('success', 'Category updated successfully.') # Matched with period

        response_get = client.get(list_url_for_get) # GET request, client handles context
        assert response_get.status_code == 200
        assert b"Category updated successfully." in response_get.data # Check flash on redirected page (with period)
        assert b"UpdatedCategoryName" in response_get.data # Check if new name is on list page

    with client.application.app_context(): # Separate context for DB check is fine
        updated_cat = db.session.get(Category, category_for_edit)
        assert updated_cat is not None
        assert updated_cat.name == 'UpdatedCategoryName'

def test_edit_category_duplicate_name(client, category_for_edit): # category_for_edit is now an ID
    with client.application.app_context():
        login_user(client, 'admin_cat@example.com', 'adminpass')
        # Create another category that will cause a name conflict
        conflicting_cat = Category(name='NewNameToConflict')
        db.session.add(conflicting_cat)
        db.session.commit()

        response = client.post(url_for('categories.edit_category', category_id=category_for_edit), data={'name': 'NewNameToConflict'}, follow_redirects=True)

    assert response.status_code == 200 # Re-renders edit form
    assert b"Category name already exists." in response.data
    assert b"Edit Category" in response.data # Still on edit page
    with client.application.app_context():
        original_cat = db.session.get(Category, category_for_edit)
        assert original_cat.name == "CategoryToEdit" # Name should not have changed

def test_edit_category_empty_name(client, category_for_edit): # category_for_edit is now an ID
    with client.application.app_context():
        login_user(client, 'admin_cat@example.com', 'adminpass')
        response = client.post(url_for('categories.edit_category', category_id=category_for_edit), data={'name': ''}, follow_redirects=True)
    assert response.status_code == 200 # Re-renders form
    assert b"This field is required." in response.data
    assert b"Edit Category" in response.data

def test_edit_category_name_too_long(client, category_for_edit): # category_for_edit is now an ID
    long_name = "b" * 81
    with client.application.app_context():
        login_user(client, 'admin_cat@example.com', 'adminpass')
        response = client.post(url_for('categories.edit_category', category_id=category_for_edit), data={'name': long_name}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Field must be between 1 and 80 characters long." in response.data
    assert b"Edit Category" in response.data

def test_edit_non_existent_category(client):
    with client.application.app_context():
        login_user(client, 'admin_cat@example.com', 'adminpass')
        response = client.get(url_for('categories.edit_category', category_id=9999))
    assert response.status_code == 404
    with client.application.app_context():
        response_post = client.post(url_for('categories.edit_category', category_id=9999), data={'name': 'GhostUpdate'})
    assert response_post.status_code == 404

# Ensure os is imported if used by SQLALCHEMY_DATABASE_URI
import os

# --- Category Deletion Tests ---

@pytest.fixture(scope="function")
def category_for_deletion(client): # Separate fixture for deletion tests
    with client.application.app_context():
        # Clean up if exists from previous run
        Category.query.filter_by(name="CategoryToDelete").delete()
        db.session.commit()

        cat = Category(name="CategoryToDelete")
        db.session.add(cat)
        db.session.commit()
        return cat.id

@pytest.fixture(scope="function")
def category_with_event(client):
    with client.application.app_context():
        Category.query.filter_by(name="CategoryWithEvent").delete()
        # Ensure no orphaned events if re-running, or create unique event
        Event.query.filter_by(title="EventInCategory").delete()
        db.session.commit()

        cat = Category(name="CategoryWithEvent")
        db.session.add(cat)
        db.session.commit() # Commit category to get its ID

        event = Event(title="EventInCategory", description="Test desc", date=datetime.utcnow(), category_id=cat.id)
        db.session.add(event)
        db.session.commit()
        return cat.id

def test_delete_category_unauthorized_user(client, category_for_deletion):
    with client.application.app_context():
        login_response = login_user(client, 'user_cat@example.com', 'userpass')
        assert login_response.status_code == 200 # Login itself should succeed

        # Check session right before the critical POST
        with client.session_transaction() as sess:
            assert sess.get('_user_id') is not None # Check if user_id is in session
            # The actual user ID might be different from email, depending on what Flask-Login stores.
            # For this test, just checking if *a* user is logged in is sufficient.
            # assert sess.get('csrf_token') is not None # Only if not WTF_CSRF_ENABLED=False

        # Prepare form data for the POST.
        # Since WTF_CSRF_ENABLED=False in test config, explicit token isn't strictly needed for validation
        # but sending form data for a form POST is good practice.
        delete_form_data = {} # DeleteCategoryForm only has a submit button.

        response = client.post(
            url_for('categories.delete_category', category_id=category_for_deletion),
            data=delete_form_data, # Send some form data
            follow_redirects=False
        )

        if response.status_code != 403:
            print(f"Unexpected status for unauthorized delete: {response.status_code}")
            try:
                print(f"Response data: {response.data.decode()}")
            except:
                print(f"Response data: {response.data}")
            with client.session_transaction() as sess:
                print(f"Session state: {dict(sess)}")


        assert response.status_code == 403

        # Clean up session by logging out
        # The existing logout route is POST only.
        logout_response = client.post(url_for('auth.logout'), follow_redirects=True)
        assert logout_response.status_code == 200 # Check that logout was successful

def test_delete_category_success(client, category_for_deletion):
    cat_id = category_for_deletion
    with client.application.app_context():
        login_user(client, 'admin_cat@example.com', 'adminpass')
        response = client.post(url_for('categories.delete_category', category_id=cat_id), follow_redirects=True)
    assert response.status_code == 200
    assert b"Category deleted successfully." in response.data
    with client.application.app_context():
        assert db.session.get(Category, cat_id) is None

def test_delete_category_with_associated_events(client, category_with_event):
    cat_id = category_with_event
    with client.application.app_context():
        login_user(client, 'admin_cat@example.com', 'adminpass')
        response = client.post(url_for('categories.delete_category', category_id=cat_id), follow_redirects=True)
    assert response.status_code == 200
    assert b"Cannot delete category: It is associated with existing events." in response.data
    with client.application.app_context():
        assert db.session.get(Category, cat_id) is not None # Category should still exist

def test_delete_non_existent_category(client):
    with client.application.app_context():
        login_user(client, 'admin_cat@example.com', 'adminpass')
        response = client.post(url_for('categories.delete_category', category_id=99999), follow_redirects=True)
    assert response.status_code == 404 # get_or_404 should trigger this
