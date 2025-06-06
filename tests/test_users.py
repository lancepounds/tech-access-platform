
import pytest

from app import create_app
from app.extensions import db


@pytest.fixture
def app():
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_user_registration(client):
    """Test user registration endpoint"""
    response = client.post('/api/users/register', 
                          json={'email': 'test@example.com', 'password': 'password123'})
    assert response.status_code == 201
    assert b'User registered successfully' in response.data


def test_user_login(client):
    """Test user login endpoint"""
    # First register a user
    client.post('/api/users/register', 
                json={'email': 'test@example.com', 'password': 'password123'})
    
    # Then login
    response = client.post('/api/users/login', 
                          json={'email': 'test@example.com', 'password': 'password123'})
    assert response.status_code == 200
    assert b'token' in response.data
