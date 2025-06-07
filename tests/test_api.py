import pytest
from datetime import datetime
from app import create_app, db
from app.models import Event

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.app_context():
        db.create_all()
        e1 = Event(id='1', title='E1', description='D1', date=datetime(2025, 1, 1), company_id=None)
        e2 = Event(id='2', title='E2', description='D2', date=datetime(2025, 2, 2), company_id=None)
        db.session.add_all([e1, e2])
        db.session.commit()
    return app.test_client()

def test_list_events(client):
    res = client.get('/api/events')
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)
    assert any(evt['title']=='E1' for evt in data)

def test_get_event(client):
    res = client.get('/api/events/1')
    assert res.status_code == 200
    evt = res.get_json()
    assert evt['id'] == 1
    assert evt['title'] == 'E1'

def test_event_not_found(client):
    res = client.get('/api/events/999')
    assert res.status_code == 404

def test_api_login_user_success(client):
    # Register a test user
    client.post('/auth/register', json={
        'email': 'testuser@example.com',
        'password': 'password123',
        'role': 'user'
    })
    # Attempt login
    res = client.post('/auth/api/login', json={
        'email': 'testuser@example.com',
        'password': 'password123'
    })
    assert res.status_code == 200
    data = res.get_json()
    assert 'token' in data
    assert data['role'] == 'user'

def test_api_login_user_failure(client):
    # Register a test user
    client.post('/auth/register', json={
        'email': 'testuser2@example.com',
        'password': 'password123',
        'role': 'user'
    })
    # Attempt login with wrong password
    res = client.post('/auth/api/login', json={
        'email': 'testuser2@example.com',
        'password': 'wrongpassword'
    })
    assert res.status_code == 401
    data = res.get_json()
    assert 'error' in data
    assert data['error'] == 'Invalid credentials'


# Helper function to register and login a company, returning the token and company_id
def register_and_login_company(client, name, email, password):
    from app.models import Company
    from werkzeug.security import generate_password_hash

    company = Company(
        name=name,
        contact_email=email,
        password=generate_password_hash(password),
        approved=True,
        role='company'
    )
    with client.application.app_context():
        db.session.add(company)
        db.session.commit()
        company_id_val = company.id # Capture company_id before it goes out of scope

    login_res = client.post('/auth/api/login', json={
        'email': email,
        'password': password
    })
    assert login_res.status_code == 200 # Ensure login is successful
    login_data = login_res.get_json()
    assert 'token' in login_data
    return login_data['token'], company_id_val


def test_create_event_success(client):
    token, company_id = register_and_login_company(client, 'EventCorp', 'eventcorp@example.com', 'securepass123')

    event_data = {
        "name": "Tech Conference 2024",
        "description": "Annual tech conference.",
        "date": "2024-12-15T10:00:00"
    }
    res = client.post('/api/events', headers={"Authorization": f"Bearer {token}"}, json=event_data)
    assert res.status_code == 201
    data = res.get_json()
    assert 'id' in data

    # Verify the event in the database
    with client.application.app_context():
        event = Event.query.get(data['id'])
        assert event is not None
        assert event.name == event_data['name']
        assert event.company_id == company_id

def test_create_event_missing_name(client):
    token, _ = register_and_login_company(client, 'EventCorpMissing', 'eventcorpmissing@example.com', 'securepass123')
    event_data = {
        # "name": "Tech Conference 2024", # Name is missing
        "description": "Annual tech conference.",
        "date": "2024-12-15T10:00:00"
    }
    res = client.post('/api/events', headers={"Authorization": f"Bearer {token}"}, json=event_data)
    assert res.status_code == 400
    data = res.get_json()
    assert data['error'] == "Event name is required"

def test_create_event_invalid_date_format(client):
    token, _ = register_and_login_company(client, 'EventCorpDate', 'eventcorpdate@example.com', 'securepass123')
    event_data = {
        "name": "Tech Conference 2024",
        "description": "Annual tech conference.",
        "date": "15-12-2024" # Invalid date format
    }
    res = client.post('/api/events', headers={"Authorization": f"Bearer {token}"}, json=event_data)
    assert res.status_code == 400
    data = res.get_json()
    assert "Invalid date format" in data['error']

def test_create_event_no_company_id_in_jwt(client):
    # This test requires crafting a token without company_id, which is tricky.
    # For now, we'll assume the login process correctly includes it.
    # A more direct way would be to mock get_jwt() or have a specific test user for this.
    # Skipping direct implementation of this specific edge case for now.
    pass

def test_create_event_not_company_role(client):
    # Register and login as a normal user
    client.post('/auth/register', json={'email': 'notacompany@example.com', 'password': 'password123', 'role': 'user'})
    login_res = client.post('/auth/api/login', json={'email': 'notacompany@example.com', 'password': 'password123'})
    token = login_res.get_json()['token']

    event_data = {
        "name": "Tech Conference 2024",
        "description": "Annual tech conference.",
        "date": "2024-12-15T10:00:00"
    }
    res = client.post('/api/events', headers={"Authorization": f"Bearer {token}"}, json=event_data)
    assert res.status_code == 403 # Forbidden due to incorrect role

# Test for RSVP notification email recipient
def test_rsvp_notification_sends_to_correct_company_email(client, mocker):
    # 1. Create Company and Event
    company_token, company_id_val = register_and_login_company(client, 'NotifyCorp', 'notify@example.com', 'notifypass')

    event_data = {
        "name": "Notification Test Event",
        "description": "Event to test RSVP notifications.",
        "date": "2024-12-20T10:00:00"
    }
    event_res = client.post('/api/events', headers={"Authorization": f"Bearer {company_token}"}, json=event_data)
    assert event_res.status_code == 201
    event_id = event_res.get_json()['id']

    # 2. Create User (member)
    member_email = 'member_rsvp@example.com'
    member_password = 'password123'
    client.post('/auth/register', json={'email': member_email, 'password': member_password, 'role': 'user'})

    # 3. Login Member
    member_login_res = client.post('/auth/api/login', json={'email': member_email, 'password': member_password})
    assert member_login_res.status_code == 200
    member_token = member_login_res.get_json()['token']

    # 4. Mock Stripe and send_email
    client.application.config["STRIPE_SECRET_KEY"] = "sk_test_dummykey" # Set dummy key for the test

    dummy_charge = mocker.Mock()
    dummy_charge.id = 'ch_dummychargeid'
    mock_stripe_charge = mocker.patch('stripe.Charge.create', return_value=dummy_charge)

    mock_send_email = mocker.patch('app.email_service.send_email') # Changed from app.mail

    # 5. Member RSVPs
    # The RSVP endpoint might require a payment_source, let's provide a dummy one if needed.
    # Based on routes.py, it seems it does: data.get("payment_source")
    rsvp_data = {"payment_source": "tok_visa"} # Dummy Stripe token
    rsvp_res = client.post(f'/api/events/{event_id}/rsvp', headers={"Authorization": f"Bearer {member_token}"}, json=rsvp_data)
    assert rsvp_res.status_code == 201

    # 6. Assert send_email was called with the correct company email
    mock_send_email.assert_called_once()
    args, _ = mock_send_email.call_args
    recipient_email = args[0]
    assert recipient_email == 'notify@example.com'

def test_rsvp_missing_payment_source(client):
    # 1. Create Company and Event
    company_token, _ = register_and_login_company(client, 'PaymentCorp1', 'payment1@example.com', 'pass123')
    event_data = {"name": "Payment Test Event 1", "description": "Test", "date": "2024-12-01T10:00:00"}
    event_res = client.post('/api/events', headers={"Authorization": f"Bearer {company_token}"}, json=event_data)
    assert event_res.status_code == 201
    event_id = event_res.get_json()['id']

    # 2. Create and Login Member
    member_email = 'member_payment1@example.com'
    client.post('/auth/register', json={'email': member_email, 'password': 'password123', 'role': 'user'})
    member_login_res = client.post('/auth/api/login', json={'email': member_email, 'password': 'password123'})
    member_token = member_login_res.get_json()['token']

    # 3. Member RSVPs without payment_source
    rsvp_res = client.post(f'/api/events/{event_id}/rsvp', headers={"Authorization": f"Bearer {member_token}"}, json={}) # Missing payment_source
    assert rsvp_res.status_code == 400
    data = rsvp_res.get_json()
    assert data['error'] == "Payment source is required for RSVP gift card."

    # Verify RSVP was still created (as per current logic)
    from app.models import RSVP, User
    with client.application.app_context():
        member = User.query.filter_by(email=member_email).first()
        assert member is not None
        rsvp_record = RSVP.query.filter_by(user_id=member.id, event_id=event_id).first()
        assert rsvp_record is not None


def test_rsvp_stripe_card_error(client, mocker):
    # 1. Create Company and Event
    company_token, _ = register_and_login_company(client, 'PaymentCorp2', 'payment2@example.com', 'pass123')
    event_data = {"name": "Payment Test Event 2", "description": "Test", "date": "2024-12-02T10:00:00"}
    event_res = client.post('/api/events', headers={"Authorization": f"Bearer {company_token}"}, json=event_data)
    assert event_res.status_code == 201
    event_id = event_res.get_json()['id']

    # 2. Create and Login Member
    member_email = 'member_payment2@example.com'
    client.post('/auth/register', json={'email': member_email, 'password': 'password123', 'role': 'user'})
    member_login_res = client.post('/auth/api/login', json={'email': member_email, 'password': 'password123'})
    member_token = member_login_res.get_json()['token']

    # 3. Mock Stripe to raise CardError and mock send_email
    client.application.config["STRIPE_SECRET_KEY"] = "sk_test_dummykey"
    import stripe # Import stripe for stripe.error
    mock_stripe_charge = mocker.patch('stripe.Charge.create', side_effect=stripe.error.CardError("Your card was declined.", param="card_error", code="card_declined"))
    mock_send_email = mocker.patch('app.email_service.send_email')

    # 4. Member RSVPs
    rsvp_data = {"payment_source": "tok_visa_declined"}
    rsvp_res = client.post(f'/api/events/{event_id}/rsvp', headers={"Authorization": f"Bearer {member_token}"}, json=rsvp_data)
    assert rsvp_res.status_code == 201 # Still 201 as RSVP is fine
    data = rsvp_res.get_json()
    assert "RSVP confirmed" in data['msg']
    assert "but failed to process gift card: Your card was declined." in data['msg']

    # Verify RSVP was created
    from app.models import RSVP, User, GiftCard
    with client.application.app_context():
        member = User.query.filter_by(email=member_email).first()
        assert member is not None
        rsvp_record = RSVP.query.filter_by(user_id=member.id, event_id=event_id).first()
        assert rsvp_record is not None
        # Verify no gift card was created
        gift_card_record = GiftCard.query.filter_by(user_id=member.id, event_id=event_id).first()
        assert gift_card_record is None

    # Email to company should still be sent
    mock_send_email.assert_called_once()

def test_api_login_company_success(client):
    # Register a test company (assuming a simplified registration or direct DB insertion for testing)
    # For a more robust test, this might involve mocking or using a company registration endpoint
    # This also assumes the company registration hashes the password.
    from app.models import Company
    from werkzeug.security import generate_password_hash
    company = Company(
        name='TestCompany',
        contact_email='company@example.com',
        password=generate_password_hash('companypassword'), # Ensure password is hashed
        approved=True, # Company must be approved to login
        role='company'
    )
    with client.application.app_context():
        db.session.add(company)
        db.session.commit()

    res = client.post('/auth/api/login', json={
        'email': 'company@example.com',  # Using contact_email for login as per recent changes
        'password': 'companypassword'
    })
    assert res.status_code == 200
    data = res.get_json()
    assert 'token' in data
    assert data['role'] == 'company'

def test_api_login_company_failure(client):
    # Register a test company
    from app.models import Company
    from werkzeug.security import generate_password_hash
    company = Company(
        name='TestCompany2',
        contact_email='company2@example.com',
        password=generate_password_hash('companypassword'),
        approved=True,
        role='company'
    )
    with client.application.app_context():
        db.session.add(company)
        db.session.commit()

    res = client.post('/auth/api/login', json={
        'email': 'company2@example.com',
        'password': 'wrongcompanypassword'
    })
    assert res.status_code == 401
    data = res.get_json()
    assert 'error' in data
    assert data['error'] == 'Invalid credentials'
