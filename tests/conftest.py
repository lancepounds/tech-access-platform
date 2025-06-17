import pytest
from app import create_app
from app.extensions import db
from app.models import User # Import User for the test_user fixture
from werkzeug.security import generate_password_hash # For test_user fixture

@pytest.fixture(scope='session')
def app():
    """Session-wide test `Flask` application."""
    # Ensure the app uses a testing configuration
    # You might need to adjust 'config.TestingConfig' if your config class is named differently
    # or if you set test-specific settings directly.
    app = create_app()
    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", # Use in-memory SQLite for tests
        "WTF_CSRF_ENABLED": False, # Often disabled for tests for simplicity
        "LOGIN_DISABLED": True, # If using Flask-Login, disable login for some tests or use test_client to log in
        "SENDGRID_MOCK": True, # Ensure emails are not actually sent
        "SERVER_NAME": "localhost.localdomain" # Required for url_for with _external=True
    })
    return app

@pytest.fixture() # Default scope is function
def test_client(app):
    """A test client for the app."""
    with app.test_client() as client:
        # The app.test_client() context manager itself handles the app context.
        # An additional app.app_context() here can lead to context pop errors.
        yield client

@pytest.fixture()
def init_database(app): # Depends on the app fixture to get app.app_context()
    """Fixture to initialize the database for each test function."""
    with app.app_context():
        db.drop_all() # Drop all tables
        db.create_all() # Create all tables
        yield db         # Provide the db object to the test if needed
        db.session.remove() # Clean up session
        # db.drop_all() # Optional: drop tables again after test, if desired

@pytest.fixture
def test_user(init_database): # Depends on init_database to ensure clean db
    """Fixture to create a test user."""
    user = User(
        email='test@example.com',
        password=generate_password_hash('password123'),
        first_name='Test',
        # Assuming 'role' defaults or is not strictly needed for these tests
        # Add other necessary fields if your User model requires them
    )
    db.session.add(user)
    db.session.commit()
    return user
