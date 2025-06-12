
import pytest
import json
from main import app, db, User
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import limiter as global_limiter_instance

@pytest.fixture
def client():
    """Create a test client for the Flask application."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            original_state = global_limiter_instance.enabled
            global_limiter_instance.enabled = False
            yield client
            global_limiter_instance.enabled = original_state
            db.drop_all()

@pytest.fixture
def sample_user():
    """Create a sample user for testing."""
    return {
        'email': 'test@example.com',
        'password': 'testpassword123',
        'firstName': 'Test',
        'lastName': 'User',
        'techExperience': 'beginner',
        'terms': True
    }

@pytest.fixture
def existing_user(client, sample_user):
    """Create an existing user in the database."""
    hashed_password = generate_password_hash(sample_user['password'])
    user = User(
        email=sample_user['email'],
        password=hashed_password,
        role='user'
    )
    db.session.add(user)
    db.session.commit()
    return user

class TestUserRegistration:
    """Test cases for user registration endpoint."""
    
    def test_register_success(self, client, sample_user):
        """Test successful user registration."""
        response = client.post('/api/users/register', 
                             json=sample_user,
                             content_type='application/json')
        
        assert response.status_code == 201
        data = json.loads(response.data)
        assert data['message'] == 'User registered successfully'
        
        # Verify user was created in database
        user = User.query.filter_by(email=sample_user['email']).first()
        assert user is not None
        assert user.email == sample_user['email']
        assert user.role == 'user'
        assert user.password != sample_user['password']
        assert check_password_hash(user.password, sample_user['password'])
    
    def test_register_missing_email(self, client):
        """Test registration with missing email."""
        data = {
            'password': 'testpassword123',
            'firstName': 'Test',
            'lastName': 'User',
            'techExperience': 'beginner',
            'terms': True
        }
        response = client.post('/api/users/register', json=data, content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Validation failed' in data['error']
        assert 'email' in data['details']
    
    def test_register_missing_password(self, client):
        """Test registration with missing password."""
        data = {
            'email': 'test@example.com',
            'firstName': 'Test',
            'lastName': 'User',
            'techExperience': 'beginner',
            'terms': True
        }
        response = client.post('/api/users/register', json=data, content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Validation failed' in data['error']
        assert 'password' in data['details']
    
    def test_register_invalid_email(self, client):
        """Test registration with invalid email format."""
        data = {
            'email': 'invalid-email',
            'password': 'testpassword123',
            'firstName': 'Test',
            'lastName': 'User',
            'techExperience': 'beginner',
            'terms': True
        }
        response = client.post('/api/users/register', json=data, content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Validation failed' in data['error']
        assert 'email' in data['details']
    
    def test_register_short_password(self, client):
        """Test registration with password too short."""
        data = {
            'email': 'test@example.com',
            'password': '123',
            'firstName': 'Test',
            'lastName': 'User',
            'techExperience': 'beginner',
            'terms': True
        }
        response = client.post('/api/users/register', json=data, content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Validation failed' in data['error']
        assert 'password' in data['details']
    
    def test_register_duplicate_email(self, client, existing_user, sample_user):
        """Test registration with already existing email."""
        response = client.post('/api/users/register',
                             json=sample_user,
                             content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['error'] == 'Email already registered'
    
    def test_register_no_json_data(self, client):
        """Test registration without JSON data."""
        response = client.post('/api/users/register')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['error'] == 'No JSON data provided'

class TestUserLogin:
    """Test cases for user login endpoint."""
    
    def test_login_success(self, client, existing_user, sample_user):
        """Test successful user login."""
        response = client.post('/api/users/login',
                             json={'email': sample_user['email'], 'password': sample_user['password']},
                             content_type='application/json')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'token' in data
        assert data['role'] == 'user'
        assert len(data['token']) > 0
    
    def test_login_invalid_email(self, client):
        """Test login with non-existent email."""
        response = client.post('/api/users/login',
                             json={
                                 'email': 'nonexistent@example.com',
                                 'password': 'testpassword123'
                             },
                             content_type='application/json')
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['error'] == 'Invalid credentials'
    
    def test_login_wrong_password(self, client, existing_user):
        """Test login with wrong password."""
        response = client.post('/api/users/login',
                             json={
                                 'email': existing_user.email,
                                 'password': 'wrongpassword'
                             },
                             content_type='application/json')
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['error'] == 'Invalid credentials'
    
    def test_login_missing_email(self, client):
        """Test login with missing email."""
        response = client.post('/api/users/login',
                             json={'password': 'testpassword123'},
                             content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Validation failed' in data['error']
        assert 'email' in data['details']
    
    def test_login_missing_password(self, client):
        """Test login with missing password."""
        response = client.post('/api/users/login',
                             json={'email': 'test@example.com'},
                             content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Validation failed' in data['error']
        assert 'password' in data['details']
    
    def test_login_invalid_email_format(self, client):
        """Test login with invalid email format."""
        response = client.post('/api/users/login',
                             json={
                                 'email': 'invalid-email',
                                 'password': 'testpassword123'
                             },
                             content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Validation failed' in data['error']
        assert 'email' in data['details']
    
    def test_login_no_json_data(self, client):
        """Test login without JSON data."""
        response = client.post('/api/users/login')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['error'] == 'No JSON data provided'

class TestUserProfile:
    """Test cases for user profile endpoint."""
    
    def get_auth_token(self, client, sample_user):
        """Helper method to get authentication token."""
        login_response = client.post(
            '/api/users/login',
            json={'email': sample_user['email'], 'password': sample_user['password']},
            content_type='application/json'
        )
        return json.loads(login_response.data)['token']
    
    def test_profile_success(self, client, existing_user, sample_user):
        """Test successful profile retrieval."""
        token = self.get_auth_token(client, sample_user)
        
        response = client.get('/api/users/profile',
                            headers={'Authorization': f'Bearer {token}'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Check all required profile fields
        assert 'id' in data
        assert 'email' in data
        assert 'role' in data
        assert 'created_at' in data
        assert 'updated_at' in data
        
        # Verify field values
        assert data['email'] == existing_user.email
        assert data['role'] == existing_user.role
        assert data['id'] == existing_user.id
        assert data['created_at'] is not None
        assert data['updated_at'] is not None
    
    def test_profile_missing_token(self, client):
        """Test profile access without authentication token."""
        response = client.get('/api/users/profile')
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['error'] == 'Missing Authorization header'
    
    def test_profile_invalid_token(self, client):
        """Test profile access with invalid token."""
        response = client.get('/api/users/profile',
                            headers={'Authorization': 'Bearer invalid-token'})
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['error'] == 'Invalid token'
    
    def test_profile_malformed_token(self, client):
        """Test profile access with malformed token."""
        response = client.get('/api/users/profile',
                            headers={'Authorization': 'InvalidFormat'})
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['error'] == 'Invalid token'
    
    def test_profile_token_without_bearer(self, client, existing_user, sample_user):
        """Test profile access with token but without Bearer prefix."""
        token = self.get_auth_token(client, sample_user)
        
        response = client.get('/api/users/profile',
                            headers={'Authorization': token})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['email'] == existing_user.email

class TestUserWorkflow:
    """Test complete user workflow: register -> login -> profile."""
    
    def test_complete_user_workflow(self, client):
        """Test complete user workflow from registration to profile access."""
        user_data = {
            'email': 'workflow@example.com',
            'password': 'workflowpassword123',
            'firstName': 'Flow',
            'lastName': 'User',
            'techExperience': 'beginner',
            'terms': True
        }
        
        # Step 1: Register user
        register_response = client.post('/api/users/register',
                                      json=user_data,
                                      content_type='application/json')
        assert register_response.status_code == 201
        
        # Step 2: Login user
        login_response = client.post(
            '/api/users/login',
            json={'email': user_data['email'], 'password': user_data['password']},
            content_type='application/json'
        )
        assert login_response.status_code == 200
        login_data = json.loads(login_response.data)
        assert 'token' in login_data
        token = login_data['token']
        
        # Step 3: Access profile
        profile_response = client.get('/api/users/profile',
                                    headers={'Authorization': f'Bearer {token}'})
        assert profile_response.status_code == 200
        profile_data = json.loads(profile_response.data)
        
        # Verify profile data matches registration
        assert profile_data['email'] == user_data['email']
        assert profile_data['role'] == 'user'
        assert 'id' in profile_data
        assert 'created_at' in profile_data
        assert 'updated_at' in profile_data
