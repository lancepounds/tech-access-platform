import pytest
from flask import Flask
from app import create_app, db
from app.models import User, Company, Category, Event, UserRole # Assuming UserRole is in app.models
from datetime import datetime, timedelta

@pytest.fixture(scope='module')
def test_app():
    """Create and configure a new app instance for each test module."""
    # Ensure the app uses a testing configuration
    app = create_app(config_name='testing')
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture(scope='module')
def client(test_app):
    """A test client for the app."""
    return test_app.test_client()

@pytest.fixture(scope='function')
def init_database(test_app):
    """Set up and tear down the database for each test function."""
    with test_app.app_context():
        # Clear data from all tables before each test
        # Order is important due to foreign key constraints
        Event.query.delete()
        Category.query.delete() # Categories might be referenced by Events
        # Users might be referenced by Events or other models
        # Be careful if User deletion affects other entities not cleaned up yet
        User.query.delete()
        Company.query.delete() # Companies might be referenced by Users

        db.session.commit() # Commit deletions

        # Recreate all tables to ensure a clean state (alternative to deleting)
        # db.drop_all()
        # db.create_all()
        # For this setup, deleting data is preferred to keep the schema intact per test_app setup.
        yield db # Provide the db session to the test

        # The teardown (clearing data) will run again after the test,
        # which is good for ensuring isolation if a test fails mid-way.

@pytest.fixture(scope='function')
def admin_user(test_app): # Depends on test_app for app_context
    with test_app.app_context():
        admin = User.query.filter_by(email='admin@example.com').first()
        if not admin:
            admin = User(
                username='adminuser',
                email='admin@example.com',
                role=UserRole.ADMIN # Ensure UserRole is correctly imported/defined
            )
            admin.set_password('adminpassword')
            db.session.add(admin)
            db.session.commit()
        return admin

@pytest.fixture(scope='function')
def regular_user(test_app): # Depends on test_app for app_context
    with test_app.app_context():
        user = User.query.filter_by(email='user@example.com').first()
        if not user:
            user = User(
                username='testuser',
                email='user@example.com',
                role=UserRole.USER
            )
            user.set_password('password')
            db.session.add(user)
            db.session.commit()
        return user

@pytest.fixture(scope='function')
def company_user(test_app): # Depends on test_app for app_context
    with test_app.app_context():
        company = Company.query.filter_by(name='Test Company').first()
        if not company:
            company = Company(name='Test Company', description='A test company')
            db.session.add(company)
            db.session.commit()

        user = User.query.filter_by(email='company@example.com').first()
        if not user:
            user = User(
                username='companyuser',
                email='company@example.com',
                role=UserRole.COMPANY,
                company_id=company.id
            )
            user.set_password('password')
            db.session.add(user)
            db.session.commit()
        return user

@pytest.fixture(scope='function')
def sample_categories(test_app): # Depends on test_app for app_context
    with test_app.app_context():
        categories_data = [
            {'name': 'Technology', 'description': 'Events related to technology'},
            {'name': 'Business', 'description': 'Events related to business'},
            {'name': 'Arts & Culture', 'description': 'Events related to arts and culture'}
        ]
        categories = []
        for cat_data in categories_data:
            category = Category.query.filter_by(name=cat_data['name']).first()
            if not category:
                category = Category(name=cat_data['name'], description=cat_data['description'])
                db.session.add(category)
            categories.append(category)
        db.session.commit()
        return categories

@pytest.fixture(scope='function')
def sample_events(test_app, sample_categories, regular_user): # Depends on test_app
    with test_app.app_context():
        # Ensure categories and user are fetched within the current session if they were created elsewhere
        db_regular_user = db.session.merge(regular_user) # Merge user to current session

        # Fetch categories by name to ensure we get session-bound objects
        cat_tech = Category.query.filter_by(name='Technology').first()
        cat_business = Category.query.filter_by(name='Business').first()

        events_data = [
            {
                'name': 'Tech Conference 2024',
                'description': 'Annual tech conference.',
                'date': datetime.utcnow() + timedelta(days=30),
                'location': 'Virtual',
                'user_id': db_regular_user.id,
                'category_id': cat_tech.id if cat_tech else None
            },
            {
                'name': 'Startup Pitch Night',
                'description': 'Pitch your startup idea.',
                'date': datetime.utcnow() + timedelta(days=45),
                'location': 'Innovation Hub',
                'user_id': db_regular_user.id,
                'category_id': cat_business.id if cat_business else None
            },
            {
                'name': 'Art Exhibition Opening',
                'description': 'Featuring local artists.',
                'date': datetime.utcnow() + timedelta(days=60),
                'location': 'City Art Gallery',
                'user_id': db_regular_user.id,
                'category_id': None # Intentionally no category
            }
        ]

        events = []
        for event_data in events_data:
            event = Event.query.filter_by(name=event_data['name']).first()
            if not event:
                event = Event(**event_data)
                db.session.add(event)
            events.append(event)
        db.session.commit()
        return events

# Basic test to ensure the file is picked up by pytest and fixtures load.
def test_example_fixture_usage(client, init_database, regular_user, sample_categories, sample_events):
    """
    A simple test to demonstrate fixture usage and basic app functionality.
    This test doesn't assert specific category logic but ensures fixtures load
    and basic relationships are sound.
    """
    assert client is not None
    # init_database is used to ensure clean db, no direct assertion on it needed here

    # Re-fetch user and categories within the test's app_context to ensure they are session-managed
    # This is good practice especially if fixtures might return detached objects
    # or if tests modify data and expect to see those changes reflected via direct model queries.

    # For this basic test, direct assertion on fixture return is fine if fixtures manage session state correctly.
    current_user = User.query.get(regular_user.id)
    assert current_user is not None
    assert current_user.username == 'testuser'

    assert len(sample_categories) == 3
    assert len(sample_events) == 3

    tech_event = Event.query.filter_by(name='Tech Conference 2024').first()
    assert tech_event is not None
    assert tech_event.category is not None
    assert tech_event.category.name == 'Technology'

    # Verify user association with the event
    assert tech_event.user_id == current_user.id
    assert tech_event.user.username == current_user.username

    # Verify an event without a category
    art_event = Event.query.filter_by(name='Art Exhibition Opening').first()
    assert art_event is not None
    assert art_event.category is None


# --- Tests for Category Creation (/categories/create) ---

def test_create_category_admin(client, test_app, init_database, admin_user):
    """Test successful category creation by an admin user."""
    with test_app.app_context():
        # Login as admin
        login_resp = client.post('/auth/login', data={
            'email': admin_user.email,
            'password': 'adminpassword'
        }, follow_redirects=True)
        assert login_resp.status_code == 200 # Assuming redirect leads to a 200 page

        category_name = 'New Category by Admin'
        category_description = 'Admin created this category.'
        response = client.post('/categories/create', data={
            'name': category_name,
            'description': category_description
        }, follow_redirects=True)

        assert response.status_code == 200 # Assuming redirect after creation leads to a 200 page (e.g., category list)

        # Check for flash message
        assert b'Category &quot;New Category by Admin&quot; created successfully.' in response.data # Check for HTML escaped message

        category = Category.query.filter_by(name=category_name).first()
        assert category is not None
        assert category.description == category_description

def test_create_category_company(client, test_app, init_database, company_user):
    """Test successful category creation by a company user."""
    with test_app.app_context():
        # Login as company user
        login_resp = client.post('/auth/login', data={
            'email': company_user.email,
            'password': 'password' # Assuming 'password' as set in fixture
        }, follow_redirects=True)
        assert login_resp.status_code == 200

        category_name = 'New Category by Company'
        category_description = 'Company created this category.'
        response = client.post('/categories/create', data={
            'name': category_name,
            'description': category_description
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'Category &quot;New Category by Company&quot; created successfully.' in response.data

        category = Category.query.filter_by(name=category_name).first()
        assert category is not None
        assert category.description == category_description

def test_create_category_regular_user_unauthorized(client, test_app, init_database, regular_user):
    """Test unauthorized category creation attempt by a regular user."""
    with test_app.app_context():
        # Login as regular user
        login_resp = client.post('/auth/login', data={
            'email': regular_user.email,
            'password': 'password' # Assuming 'password' as set in fixture
        }, follow_redirects=True)
        assert login_resp.status_code == 200

        initial_category_count = Category.query.count()

        response = client.post('/categories/create', data={
            'name': 'Unauthorized Category',
            'description': 'This should not be created.'
        }, follow_redirects=True)

        assert response.status_code == 403 # Expecting Forbidden

        assert Category.query.count() == initial_category_count
        category = Category.query.filter_by(name='Unauthorized Category').first()
        assert category is None

def test_create_category_duplicate_name(client, test_app, init_database, admin_user, sample_categories):
    """Test creating a category that already exists."""
    with test_app.app_context():
        # Login as admin
        client.post('/auth/login', data={'email': admin_user.email, 'password': 'adminpassword'})

        existing_category = sample_categories[0] # Take one from fixture
        initial_category_count = Category.query.count()

        response = client.post('/categories/create', data={
            'name': existing_category.name,
            'description': 'Attempting to duplicate.'
        }, follow_redirects=True)

        assert response.status_code == 200 # Form re-rendered with error
        assert b'Category with this name already exists.' in response.data # Example flash message
        assert Category.query.count() == initial_category_count # No new category created

def test_create_category_form_validation(client, test_app, init_database, admin_user):
    """Test form validation for category creation (e.g., empty name, name too long)."""
    with test_app.app_context():
        # Login as admin
        client.post('/auth/login', data={'email': admin_user.email, 'password': 'adminpassword'})

        initial_category_count = Category.query.count()

        # Test empty name
        response_empty_name = client.post('/categories/create', data={
            'name': '',
            'description': 'Test description'
        }, follow_redirects=True)
        assert response_empty_name.status_code == 200 # Form re-rendered
        assert b'This field is required.' in response_empty_name.data # WTForms default message for NotEmpty
        assert Category.query.count() == initial_category_count

        # Test name too long (assuming max length is e.g. 80 chars for Category.name)
        long_name = 'a' * 81 # Assuming Category.name has String(80)
        # If no specific max length on model, this part of test might behave differently
        # or rely on a general reasonable limit if any is enforced by WTForms.
        # For this example, let's assume Category.name = db.Column(db.String(80), unique=True, nullable=False)

        response_long_name = client.post('/categories/create', data={
            'name': long_name,
            'description': 'Test description for long name'
        }, follow_redirects=True)
        assert response_long_name.status_code == 200 # Form re-rendered
        # The exact message depends on how WTForms Length validator is configured
        assert b'Field cannot be longer than 80 characters.' in response_long_name.data # Example error
        assert Category.query.count() == initial_category_count


# --- Tests for Category Listing (/categories/) ---

def test_list_categories_admin(client, test_app, init_database, admin_user, sample_categories):
    """Test admin user can list categories and sees admin controls (e.g., delete buttons)."""
    with test_app.app_context():
        client.post('/auth/login', data={'email': admin_user.email, 'password': 'adminpassword'})

        response = client.get('/categories/')
        assert response.status_code == 200
        response_data = response.data.decode('utf-8')

        for category in sample_categories:
            assert category.name in response_data
            # Example: Check for a delete form specific to admin for each category
            assert f'<form method="post" action="/categories/{category.id}/delete">' in response_data
            assert 'Delete' in response_data # General check for delete text

def test_list_categories_company(client, test_app, init_database, company_user, sample_categories):
    """Test company user can list categories but does not see admin controls."""
    with test_app.app_context():
        client.post('/auth/login', data={'email': company_user.email, 'password': 'password'})

        response = client.get('/categories/')
        assert response.status_code == 200
        response_data = response.data.decode('utf-8')

        for category in sample_categories:
            assert category.name in response_data
            # Ensure delete forms/buttons are NOT present for company user
            assert f'<form method="post" action="/categories/{category.id}/delete">' not in response_data

        # Check for presence of "Create Category" button if company users are allowed to create
        # This depends on specific app logic, for now, we focus on listing and absence of delete.
        # assert 'Create Category' in response_data

def test_list_categories_regular_user(client, test_app, init_database, regular_user, sample_categories):
    """Test regular user can list categories but does not see admin controls."""
    with test_app.app_context():
        client.post('/auth/login', data={'email': regular_user.email, 'password': 'password'})

        response = client.get('/categories/')
        assert response.status_code == 200
        response_data = response.data.decode('utf-8')

        for category in sample_categories:
            assert category.name in response_data
            # Ensure delete forms/buttons are NOT present for regular user
            assert f'<form method="post" action="/categories/{category.id}/delete">' not in response_data

def test_list_categories_empty(client, test_app, init_database, admin_user):
    """Test listing categories when no categories exist in the database."""
    with test_app.app_context():
        # Ensure no categories are present (init_database fixture already clears them)
        assert Category.query.count() == 0

        client.post('/auth/login', data={'email': admin_user.email, 'password': 'adminpassword'})

        response = client.get('/categories/')
        assert response.status_code == 200
        response_data = response.data.decode('utf-8')

        assert "No categories found." in response_data # Or similar message
        # Check that the loop for categories wouldn't render anything, e.g. no <tr> for category data if it's a table
        # This depends heavily on template structure. A simple text check is often sufficient.


# --- Tests for Category Editing (/categories/<id>/edit) ---

def test_edit_category_admin(client, test_app, init_database, admin_user, sample_categories):
    """Test successful category update by an admin user."""
    with test_app.app_context():
        client.post('/auth/login', data={'email': admin_user.email, 'password': 'adminpassword'})

        category_to_edit = sample_categories[0]
        original_name = category_to_edit.name
        edit_url = f'/categories/{category_to_edit.id}/edit'

        # Test GET request for the edit page
        response_get = client.get(edit_url)
        assert response_get.status_code == 200
        response_get_data = response_get.data.decode('utf-8')
        assert f'value="{category_to_edit.name}"' in response_get_data
        assert category_to_edit.description in response_get_data # Check if description is in textarea

        # Test POST request to update the category
        updated_name = "Updated Category Name by Admin"
        updated_description = "This category has been updated by an admin."
        response_post = client.post(edit_url, data={
            'name': updated_name,
            'description': updated_description
        }, follow_redirects=True)

        assert response_post.status_code == 200 # Assuming redirect to a list page or similar
        assert f'Category &quot;{updated_name}&quot; updated successfully.' in response_post.data

        updated_category_from_db = Category.query.get(category_to_edit.id)
        assert updated_category_from_db is not None
        assert updated_category_from_db.name == updated_name
        assert updated_category_from_db.description == updated_description
        assert updated_category_from_db.name != original_name

def test_edit_category_regular_user_unauthorized(client, test_app, init_database, regular_user, sample_categories):
    """Test unauthorized edit attempt by a regular user."""
    with test_app.app_context():
        client.post('/auth/login', data={'email': regular_user.email, 'password': 'password'})

        category_to_edit = sample_categories[0]
        original_name = category_to_edit.name
        edit_url = f'/categories/{category_to_edit.id}/edit'

        # Test GET request
        response_get = client.get(edit_url)
        assert response_get.status_code == 403

        # Test POST request
        response_post = client.post(edit_url, data={
            'name': 'Attempt by Regular User',
            'description': 'Should not happen'
        })
        assert response_post.status_code == 403

        category_from_db = Category.query.get(category_to_edit.id)
        assert category_from_db.name == original_name # Name should be unchanged

def test_edit_category_company_user_unauthorized(client, test_app, init_database, company_user, sample_categories):
    """Test unauthorized edit attempt by a company user."""
    with test_app.app_context():
        client.post('/auth/login', data={'email': company_user.email, 'password': 'password'})

        category_to_edit = sample_categories[0]
        original_name = category_to_edit.name
        edit_url = f'/categories/{category_to_edit.id}/edit'

        # Test GET request
        response_get = client.get(edit_url)
        assert response_get.status_code == 403

        # Test POST request
        response_post = client.post(edit_url, data={
            'name': 'Attempt by Company User',
            'description': 'Should not happen'
        })
        assert response_post.status_code == 403

        category_from_db = Category.query.get(category_to_edit.id)
        assert category_from_db.name == original_name # Name should be unchanged

def test_edit_category_duplicate_name(client, test_app, init_database, admin_user, sample_categories):
    """Test editing a category to a name that already exists."""
    with test_app.app_context():
        client.post('/auth/login', data={'email': admin_user.email, 'password': 'adminpassword'})

        # sample_categories fixture creates 'Technology', 'Business', 'Arts & Culture'
        category_to_edit = Category.query.filter_by(name='Technology').first() # Category A
        existing_name_for_conflict = Category.query.filter_by(name='Business').first().name # Category B's name

        original_name_of_category_A = category_to_edit.name
        edit_url = f'/categories/{category_to_edit.id}/edit'

        response = client.post(edit_url, data={
            'name': existing_name_for_conflict, # Attempt to rename 'Technology' to 'Business'
            'description': category_to_edit.description
        }, follow_redirects=True)

        assert response.status_code == 200 # Form re-rendered with error
        assert b'Category with this name already exists.' in response.data

        category_A_from_db = Category.query.get(category_to_edit.id)
        assert category_A_from_db.name == original_name_of_category_A # Name should be unchanged

def test_edit_category_non_existent(client, test_app, init_database, admin_user):
    """Test editing a non-existent category."""
    with test_app.app_context():
        client.post('/auth/login', data={'email': admin_user.email, 'password': 'adminpassword'})

        non_existent_id = 9999
        edit_url = f'/categories/{non_existent_id}/edit'

        # Test GET request
        response_get = client.get(edit_url)
        assert response_get.status_code == 404

        # Test POST request
        response_post = client.post(edit_url, data={
            'name': 'Trying to edit non-existent',
            'description': 'Should 404'
        })
        assert response_post.status_code == 404

def test_edit_category_form_validation(client, test_app, init_database, admin_user, sample_categories):
    """Test form validation when editing a category."""
    with test_app.app_context():
        client.post('/auth/login', data={'email': admin_user.email, 'password': 'adminpassword'})

        category_to_edit = sample_categories[0]
        original_name = category_to_edit.name
        edit_url = f'/categories/{category_to_edit.id}/edit'

        # Test empty name
        response_empty_name = client.post(edit_url, data={
            'name': '',
            'description': 'Some description'
        }, follow_redirects=True)
        assert response_empty_name.status_code == 200 # Form re-rendered
        assert b'This field is required.' in response_empty_name.data
        db_category = Category.query.get(category_to_edit.id)
        assert db_category.name == original_name # Name unchanged

        # Test name too long (assuming max length 80 for Category.name)
        long_name = 'b' * 81
        response_long_name = client.post(edit_url, data={
            'name': long_name,
            'description': 'Some description'
        }, follow_redirects=True)
        assert response_long_name.status_code == 200 # Form re-rendered
        assert b'Field cannot be longer than 80 characters.' in response_long_name.data
        db_category = Category.query.get(category_to_edit.id)
        assert db_category.name == original_name # Name unchanged


# --- Tests for Category Deletion (/categories/<id>/delete) ---

def test_delete_unused_category_admin(client, test_app, init_database, admin_user):
    """Test successful deletion of an unused category by an admin user."""
    with test_app.app_context():
        client.post('/auth/login', data={'email': admin_user.email, 'password': 'adminpassword'})

        # Create a new category not associated with any events
        cat_name = "Category to Delete"
        category_to_delete = Category(name=cat_name, description="This will be deleted.")
        db.session.add(category_to_delete)
        db.session.commit()
        category_id = category_to_delete.id
        assert Category.query.get(category_id) is not None # Ensure it's in DB

        delete_url = f'/categories/{category_id}/delete'
        # To pass form.validate_on_submit() for a DeleteForm which might only have CSRF,
        # we need to simulate a form submission that includes the CSRF token.
        # The test client usually handles CSRF automatically if WTForms integration is set up correctly in the app.
        # If it's not, we'd need to fetch the token from a page that has the form first.
        # For now, assume client.post with follow_redirects handles CSRF or it's implicitly valid for such simple forms.
        # A more robust way if CSRF is strict is to GET a page with the form, parse token, then POST.
        # However, given the route snippet, an empty POST will fail CSRF.
        # For a *successful* deletion, the form must be valid. We'll send an empty dict,
        # which should pass if the test client handles CSRF transparently for WTForms.
        # If this fails due to CSRF, it means the test setup needs to be more specific about CSRF token handling.
        # Let's assume for a POST to a delete endpoint, it's often a direct POST without needing to GET a form page first.
        # The route's DeleteCategoryForm() is likely just for CSRF.

        # To properly test with CSRF, one would typically:
        # 1. GET a page that includes the DeleteCategoryForm (e.g., the category list page might have delete buttons in forms)
        # 2. Extract the CSRF token from that form.
        # 3. POST to the delete URL including that CSRF token.
        # For simplicity here, if the test client handles CSRF tokens automatically with WTForms, data={} might be enough.
        # If not, this test might incorrectly fail the CSRF check.
        # The provided route logic suggests `form.validate_on_submit()` is key.
        # Flask-WTF's `validate_on_submit` checks both `is_submitted()` and `validate()`.
        # `is_submitted()` checks if it's a POST/PUT/PATCH/DELETE. `validate()` runs validators.
        # A CSRF token is implicitly added by Flask-WTF and validated.
        # The test client often submits necessary tokens automatically.

        response = client.post(delete_url, follow_redirects=True)

        assert response.status_code == 200 # Redirect to list page
        assert f'Category &quot;{cat_name}&quot; deleted successfully.' in response.data
        assert Category.query.get(category_id) is None

def test_delete_category_regular_user_unauthorized(client, test_app, init_database, regular_user, sample_categories):
    """Test unauthorized deletion attempt by a regular user."""
    with test_app.app_context():
        client.post('/auth/login', data={'email': regular_user.email, 'password': 'password'})

        category_to_delete = sample_categories[0]
        delete_url = f'/categories/{category_to_delete.id}/delete'

        response = client.post(delete_url)
        assert response.status_code == 403
        assert Category.query.get(category_to_delete.id) is not None # Not deleted

def test_delete_category_company_user_unauthorized(client, test_app, init_database, company_user, sample_categories):
    """Test unauthorized deletion attempt by a company user."""
    with test_app.app_context():
        client.post('/auth/login', data={'email': company_user.email, 'password': 'password'})

        category_to_delete = sample_categories[0]
        delete_url = f'/categories/{category_to_delete.id}/delete'

        response = client.post(delete_url)
        assert response.status_code == 403
        assert Category.query.get(category_to_delete.id) is not None # Not deleted

def test_delete_non_existent_category_admin(client, test_app, init_database, admin_user):
    """Test deleting a non-existent category by an admin."""
    with test_app.app_context():
        client.post('/auth/login', data={'email': admin_user.email, 'password': 'adminpassword'})

        non_existent_id = 99999
        delete_url = f'/categories/{non_existent_id}/delete'

        response = client.post(delete_url)
        assert response.status_code == 404

def test_delete_category_with_events_admin(client, test_app, init_database, admin_user, sample_categories, sample_events):
    """Test attempting to delete a category that is associated with events."""
    with test_app.app_context():
        client.post('/auth/login', data={'email': admin_user.email, 'password': 'adminpassword'})

        # The 'Technology' category is typically linked to 'Tech Conference 2024' by sample_events
        category_with_event = Category.query.filter_by(name='Technology').first()
        assert category_with_event is not None
        assert len(category_with_event.events) > 0 # Verify it has events

        delete_url = f'/categories/{category_with_event.id}/delete'
        response = client.post(delete_url, follow_redirects=True)

        assert response.status_code == 200 # Redirect to list page
        assert b'Cannot delete category: it is associated with one or more events.' in response.data
        assert Category.query.get(category_with_event.id) is not None # Not deleted

def test_delete_category_csrf_protection(client, test_app, init_database, admin_user, sample_categories):
    """Test CSRF protection on category deletion route."""
    with test_app.app_context():
        client.post('/auth/login', data={'email': admin_user.email, 'password': 'adminpassword'})

        category_to_delete = sample_categories[0]
        delete_url = f'/categories/{category_to_delete.id}/delete'

        # To simulate a missing/invalid CSRF token with WTForms, we can disable the test client's CSRF handling
        # or POST without any form data if the form is just for CSRF.
        # The route code has an `else` for `form.validate_on_submit()`.
        # If `WTF_CSRF_ENABLED` is True (default) and `WTF_CSRF_CHECK_DEFAULT` is True (default),
        # a POST without a CSRF token field will fail validation.
        # The test client might automatically include CSRF tokens.
        # To bypass this for testing the *failure* of CSRF, we might need to configure the client or app.
        # A simpler way: if DeleteCategoryForm is truly empty (no fields other than CSRF),
        # then posting `data={}` *should* fail `form.validate_on_submit()` if CSRF is not auto-added or is invalid.
        # Let's assume `client.post(url)` without `data` or with `data={}` makes the form invalid.

        # Temporarily disable CSRF protection in the app config for this specific test.
        # This is generally not ideal, but can be a way to test the specific path.
        # A better way is if the test client has an option to not submit CSRF.
        # For now, let's rely on the provided route logic:
        # if form.validate_on_submit(): -> this will be false if CSRF is missing.

        # Flask test client does not automatically include CSRF tokens unless specifically configured with Flask-Testing or similar.
        # So, a plain post() without the token in `data` should fail.
        response = client.post(delete_url, data={}, follow_redirects=True) # data={} means no CSRF token submitted explicitly

        assert response.status_code == 200 # Redirect to list page
        assert b'Invalid request for deletion.' in response.data # Flash message from the `else` block
        assert Category.query.get(category_to_delete.id) is not None # Not deleted
