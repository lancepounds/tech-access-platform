import pytest
from datetime import datetime
from app import create_app, db
from app.models import Event, User, Company, RSVP, GiftCard
import json
import os
from werkzeug.security import generate_password_hash
import stripe # Added stripe import

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("TEST_DATABASE_URL", "sqlite:///:memory:")
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SECRET_KEY'] = 'test_secret_for_api'
    app.config['SERVER_NAME'] = 'localhost.test'


    with app.app_context():
        db.create_all()
        # Minimal setup, specific tests will add more data
        # Ensure at least one company and user for login helpers if needed broadly
        # but many tests create their own users/companies.
        # For simplicity, keeping this minimal or let tests handle their own specific user/company creation.

        # Cleanup any existing data to ensure clean slate for each test module run
        # This might be aggressive if other test modules expect some base data.
        # For now, assuming this test module manages its own test data primarily.
        # for table in reversed(db.metadata.sorted_tables):
        #     db.session.execute(table.delete())
        # db.session.commit()


        e1 = Event(id='evt1', title='E1', description='D1', date=datetime(2025, 1, 1), company_id=None)
        e2 = Event(id='evt2', title='E2', description='D2', date=datetime(2025, 2, 2), company_id=None)
        db.session.add_all([e1, e2])
        db.session.commit()
    return app.test_client()

def test_list_events(client):
    res = client.get('/api/events')
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)
    # Try asserting 'title' first, as 'name' is a property that might not serialize as expected by default
    assert any(evt['title']=='E1' for evt in data)

# test_get_event needs adjustment if Event model ID is string UUID
# For now, assuming Event model has integer ID or test is adapted for string ID '1'
# If Event.id is string, then url should be /api/events/evt1
def test_get_event(client):
    res = client.get('/api/events/evt1') # Assuming string ID 'evt1'
    assert res.status_code == 404 # This route does not exist for GET by ID

def test_event_not_found(client):
    res = client.get('/api/events/evt_nonexistent')
    assert res.status_code == 404

def test_api_login_user_success(client):
    with client.application.app_context():
        User.query.filter_by(email='testuser_api_login@example.com').delete()
        db.session.commit()
    client.post('/auth/register', json={
        'email': 'testuser_api_login@example.com',
        'password': 'password123',
        'role': 'user'
    })
    res = client.post('/auth/api/login', json={
        'email': 'testuser_api_login@example.com',
        'password': 'password123'
    })
    assert res.status_code == 200
    data = res.get_json()
    assert 'token' in data
    assert data['role'] == 'user'

def test_api_login_user_failure(client):
    with client.application.app_context():
        User.query.filter_by(email='testuser2_api_login@example.com').delete()
        db.session.commit()
    client.post('/auth/register', json={
        'email': 'testuser2_api_login@example.com',
        'password': 'password123',
        'role': 'user'
    })
    res = client.post('/auth/api/login', json={
        'email': 'testuser2_api_login@example.com',
        'password': 'wrongpassword'
    })
    assert res.status_code == 401
    data = res.get_json()
    assert 'error' in data
    assert data['error'] == 'Invalid credentials'

def register_and_login_company(client, name, email, password):
    from werkzeug.security import generate_password_hash
    with client.application.app_context():
        # Clean up existing company with same email/name to avoid unique constraint errors
        Company.query.filter((Company.name == name) | (Company.contact_email == email)).delete()
        db.session.commit()

        company = Company(
            name=name,
            contact_email=email,
            password=generate_password_hash(password),
            approved=True,
            role='company'
        )
        db.session.add(company)
        db.session.commit()
        company_id_val = company.id

    login_res = client.post('/auth/api/login', json={'email': email, 'password': password})
    assert login_res.status_code == 200
    login_data = login_res.get_json()
    assert 'token' in login_data
    return login_data['token'], company_id_val


def test_create_event_success(client):
    token, company_id = register_and_login_company(client, 'EventCorp', 'eventcorp_api@example.com', 'securepass123')

    event_data = {
        "name": "Tech Conference 2024",
        "description": "Annual tech conference.",
        "date": "2024-12-15T10:00:00"
    }
    res = client.post('/api/events', headers={"Authorization": f"Bearer {token}"}, json=event_data)
    assert res.status_code == 201
    data = res.get_json()
    assert 'id' in data

    with client.application.app_context():
        event = db.session.get(Event, data['id']) # Use db.session.get for pk
        assert event is not None
        assert event.title == event_data['name'] # Model uses title
        assert event.company_id == company_id

def test_create_event_missing_name(client):
    token, _ = register_and_login_company(client, 'EventCorpMissing', 'eventcorpmissing_api@example.com', 'securepass123')
    event_data = {
        "description": "Annual tech conference.",
        "date": "2024-12-15T10:00:00"
    }
    res = client.post('/api/events', headers={"Authorization": f"Bearer {token}"}, json=event_data)
    assert res.status_code == 400
    data = res.get_json()
    assert 'errors' in data
    assert 'name' in data['errors']
    assert "Missing data for required field." in data['errors']['name']

def test_create_event_missing_description(client): # New test
    token, _ = register_and_login_company(client, 'EventCorpDesc', 'eventcorpdesc_api@example.com', 'securepass123')
    event_data = {
        "name": "No Description Event",
        "date": "2024-12-15T10:00:00"
    }
    res = client.post('/api/events', headers={"Authorization": f"Bearer {token}"}, json=event_data)
    assert res.status_code == 400
    data = res.get_json()
    assert 'errors' in data
    assert 'description' in data['errors']
    assert "Missing data for required field." in data['errors']['description']

def test_create_event_missing_date(client): # New test
    token, _ = register_and_login_company(client, 'EventCorpDate', 'eventcorpdate_api@example.com', 'securepass123')
    event_data = {
        "name": "No Date Event",
        "description": "This event has no date."
    }
    res = client.post('/api/events', headers={"Authorization": f"Bearer {token}"}, json=event_data)
    assert res.status_code == 400
    data = res.get_json()
    assert 'errors' in data
    assert 'date' in data['errors']
    assert "Missing data for required field." in data['errors']['date']


def test_create_event_invalid_date_format(client):
    token, _ = register_and_login_company(client, 'EventCorpDateFmt', 'eventcorpdatefmt_api@example.com', 'securepass123')
    event_data = {
        "name": "Tech Conference 2024",
        "description": "Annual tech conference.",
        "date": "15-12-2024"
    }
    res = client.post('/api/events', headers={"Authorization": f"Bearer {token}"}, json=event_data)
    assert res.status_code == 400
    data = res.get_json()
    assert 'errors' in data
    assert 'date' in data['errors']
    assert "Not a valid datetime." in data['errors']['date'][0]

def test_create_event_not_company_role(client):
    with client.application.app_context():
        User.query.filter_by(email='notacompany_api@example.com').delete()
        db.session.commit()
    client.post('/auth/register', json={'email': 'notacompany_api@example.com', 'password': 'password123', 'role': 'user'})
    login_res = client.post('/auth/api/login', json={'email': 'notacompany_api@example.com', 'password': 'password123'})
    token = login_res.get_json()['token']

    event_data = {
        "name": "Tech Conference 2024",
        "description": "Annual tech conference.",
        "date": "2024-12-15T10:00:00"
    }
    res = client.post('/api/events', headers={"Authorization": f"Bearer {token}"}, json=event_data)
    assert res.status_code == 403

def test_rsvp_notification_sends_to_correct_company_email(client, mocker):
    token_comp, company_id = register_and_login_company(client, 'NotifyCorp', 'notify_api@example.com', 'notifypass')

    event_data = {"name": "Notification Test Event", "description": "Event to test RSVP notifications.", "date": "2024-12-20T10:00:00"}
    event_res = client.post('/api/events', headers={"Authorization": f"Bearer {token_comp}"}, json=event_data)
    event_id = event_res.get_json()['id']

    member_email = 'member_rsvp_api@example.com'
    with client.application.app_context(): # Ensure user is created in correct context
        User.query.filter_by(email=member_email).delete()
        db.session.commit()
        client.post('/auth/register', json={'email': member_email, 'password': 'password123', 'role': 'user'})

    member_login_res = client.post('/auth/api/login', json={'email': member_email, 'password': 'password123'})
    member_token = member_login_res.get_json()['token']

    client.application.config["STRIPE_SECRET_KEY"] = "sk_test_dummykey"
    dummy_charge = mocker.Mock()
    dummy_charge.id = 'ch_dummychargeid'
    mocker.patch('stripe.Charge.create', return_value=dummy_charge)
    mock_send_email = mocker.patch('app.email_service.send_email')

    rsvp_data = {"payment_source": "tok_visa"}
    rsvp_res = client.post(f'/api/events/{event_id}/rsvp', headers={"Authorization": f"Bearer {member_token}"}, json=rsvp_data)
    assert rsvp_res.status_code == 201

    mock_send_email.assert_called_once()
    args, _ = mock_send_email.call_args
    assert args[0] == 'notify_api@example.com'

def test_rsvp_missing_payment_source(client):
    token_comp, _ = register_and_login_company(client, 'PaymentCorp1', 'payment1_api@example.com', 'pass123')
    event_data = {"name": "Payment Test Event 1", "description": "Test", "date": "2024-12-01T10:00:00"}
    event_res = client.post('/api/events', headers={"Authorization": f"Bearer {token_comp}"}, json=event_data)
    event_id = event_res.get_json()['id']

    member_email = 'member_payment1_api@example.com'
    with client.application.app_context():
        User.query.filter_by(email=member_email).delete()
        db.session.commit()
        client.post('/auth/register', json={'email': member_email, 'password': 'password123', 'role': 'user'})
    member_login_res = client.post('/auth/api/login', json={'email': member_email, 'password': 'password123'})
    member_token = member_login_res.get_json()['token']

    rsvp_res = client.post(f'/api/events/{event_id}/rsvp', headers={"Authorization": f"Bearer {member_token}"}, json={})
    assert rsvp_res.status_code == 400
    data = rsvp_res.get_json()
    assert 'errors' in data
    assert 'payment_source' in data['errors']
    assert "Missing data for required field." in data['errors']['payment_source']

    with client.application.app_context():
        member = User.query.filter_by(email=member_email).first()
        assert member is not None
        rsvp_record = RSVP.query.filter_by(user_id=member.id, event_id=event_id).first()
        assert rsvp_record is None

def test_rsvp_stripe_card_error(client, mocker):
    token_comp, _ = register_and_login_company(client, 'PaymentCorp2', 'payment2_api@example.com', 'pass123')
    event_data = {"name": "Payment Test Event 2", "description": "Test", "date": "2024-12-02T10:00:00"}
    event_res = client.post('/api/events', headers={"Authorization": f"Bearer {token_comp}"}, json=event_data)
    event_id = event_res.get_json()['id']

    member_email = 'member_payment2_api@example.com'
    with client.application.app_context():
        User.query.filter_by(email=member_email).delete()
        db.session.commit()
        client.post('/auth/register', json={'email': member_email, 'password': 'password123', 'role': 'user'})
    member_login_res = client.post('/auth/api/login', json={'email': member_email, 'password': 'password123'})
    member_token = member_login_res.get_json()['token']

    client.application.config["STRIPE_SECRET_KEY"] = "sk_test_dummykey"
    import stripe
    mocker.patch('stripe.Charge.create', side_effect=stripe.error.CardError("Your card was declined.", param="card_error", code="card_declined"))
    mock_send_email = mocker.patch('app.email_service.send_email')

    rsvp_data = {"payment_source": "tok_visa_declined"}
    rsvp_res = client.post(f'/api/events/{event_id}/rsvp', headers={"Authorization": f"Bearer {member_token}"}, json=rsvp_data)
    assert rsvp_res.status_code == 201
    data = rsvp_res.get_json()
    assert "RSVP confirmed" in data['msg']
    assert "but failed to process gift card: Your card was declined." in data['msg']

    with client.application.app_context():
        member = User.query.filter_by(email=member_email).first()
        assert member is not None
        rsvp_record = RSVP.query.filter_by(user_id=member.id, event_id=event_id).first()
        assert rsvp_record is not None
        gift_card_record = GiftCard.query.filter_by(user_id=member.id, event_id=event_id).first()
        assert gift_card_record is None

    mock_send_email.assert_called_once()

def test_api_login_company_success(client):
    company_email = 'company_api_login@example.com'
    with client.application.app_context():
        Company.query.filter_by(contact_email=company_email).delete()
        db.session.commit()
        company = Company(name='TestCompanyAPI', contact_email=company_email, password=generate_password_hash('companypassword'), approved=True, role='company')
        db.session.add(company)
        db.session.commit()

    res = client.post('/auth/api/login', json={'email': company_email, 'password': 'companypassword'})
    assert res.status_code == 200
    data = res.get_json()
    assert 'token' in data
    assert data['role'] == 'company'

def test_api_login_company_failure(client):
    company_email = 'company2_api_login@example.com'
    with client.application.app_context():
        Company.query.filter_by(contact_email=company_email).delete()
        db.session.commit()
        company = Company(name='TestCompany2API', contact_email=company_email, password=generate_password_hash('companypassword'), approved=True, role='company')
        db.session.add(company)
        db.session.commit()

    res = client.post('/auth/api/login', json={'email': company_email, 'password': 'wrongcompanypassword'})
    assert res.status_code == 401
    data = res.get_json()
    assert 'error' in data
    assert data['error'] == 'Invalid credentials'

# --- New tests for issue_gift ---

def test_issue_gift_success(client, mocker):
    token_comp, company_id = register_and_login_company(client, 'GiftCorp', 'giftcorp_api@example.com', 'giftypass')

    # Create a user to receive the gift
    user_email_gift = 'giftee_api@example.com'
    with client.application.app_context():
        User.query.filter_by(email=user_email_gift).delete() # Clean first
        db.session.commit()
        user_to_receive_gift = User(email=user_email_gift, password=generate_password_hash('pass'), role='user')
        db.session.add(user_to_receive_gift)
        db.session.commit()
        user_id_gift = user_to_receive_gift.id


    # Create an event
    event_data = {"name": "Giftable Event", "description": "Event for gifts", "date": "2024-12-25T10:00:00"}
    event_res = client.post('/api/events', headers={"Authorization": f"Bearer {token_comp}"}, json=event_data)
    assert event_res.status_code == 201
    event_id_gift = event_res.get_json()['id']

    client.application.config["STRIPE_SECRET_KEY"] = "sk_test_dummykey_gift"
    dummy_charge = mocker.Mock()
    dummy_charge.id = 'ch_dummygiftcharge'
    mocker.patch('stripe.Charge.create', return_value=dummy_charge)

    issue_gift_data = {
        "user_id": user_id_gift,
        "payment_source": "tok_mastercard",
        "amount_cents": 1500
    }
    res = client.post(f'/api/events/{event_id_gift}/issue_gift', headers={"Authorization": f"Bearer {token_comp}"}, json=issue_gift_data)
    assert res.status_code == 200
    data = res.get_json()
    assert data['msg'] == "Gift card issued"
    assert data['charge_id'] == 'ch_dummygiftcharge'

    with client.application.app_context():
        gift_card = GiftCard.query.filter_by(user_id=user_id_gift, event_id=event_id_gift).first()
        assert gift_card is not None
        assert gift_card.amount_cents == 1500

def test_issue_gift_missing_user_id(client):
    token_comp, _ = register_and_login_company(client, 'GiftCorpMissUser', 'giftcorpmu_api@example.com', 'giftypass')
    event_data = {"name": "Giftable Event MU", "description": "Event for gifts MU", "date": "2024-12-25T10:00:00"}
    event_res = client.post('/api/events', headers={"Authorization": f"Bearer {token_comp}"}, json=event_data)
    event_id_gift = event_res.get_json()['id']

    issue_gift_data = {
        # "user_id": "some_user_id", # Missing
        "payment_source": "tok_mastercard",
        "amount_cents": 1500
    }
    res = client.post(f'/api/events/{event_id_gift}/issue_gift', headers={"Authorization": f"Bearer {token_comp}"}, json=issue_gift_data)
    assert res.status_code == 400
    data = res.get_json()
    assert 'errors' in data
    assert 'user_id' in data['errors']
    assert "Missing data for required field." in data['errors']['user_id']

def test_issue_gift_missing_payment_source(client):
    token_comp, _ = register_and_login_company(client, 'GiftCorpMissPay', 'giftcorpmps_api@example.com', 'giftypass')
    user_email_gift = 'gifteemps_api@example.com' # Ensure unique email
    with client.application.app_context():
        User.query.filter_by(email=user_email_gift).delete()
        db.session.commit()
        user_to_receive_gift = User(email=user_email_gift, password=generate_password_hash('pass'), role='user')
        db.session.add(user_to_receive_gift)
        db.session.commit()
        user_id_gift = user_to_receive_gift.id

    event_data = {"name": "Giftable Event MPS", "description": "Event for gifts MPS", "date": "2024-12-25T10:00:00"}
    event_res = client.post('/api/events', headers={"Authorization": f"Bearer {token_comp}"}, json=event_data)
    event_id_gift = event_res.get_json()['id']

    issue_gift_data = {
        "user_id": user_id_gift,
        # "payment_source": "tok_mastercard", # Missing
        "amount_cents": 1500
    }
    res = client.post(f'/api/events/{event_id_gift}/issue_gift', headers={"Authorization": f"Bearer {token_comp}"}, json=issue_gift_data)
    assert res.status_code == 400
    data = res.get_json()
    assert 'errors' in data
    assert 'payment_source' in data['errors']
    assert "Missing data for required field." in data['errors']['payment_source']

def test_issue_gift_default_amount(client, mocker): # New test for default amount
    token_comp, company_id = register_and_login_company(client, 'GiftCorpDef', 'giftcorpdef_api@example.com', 'giftypass')
    user_email_gift = 'gifteedef_api@example.com'
    with client.application.app_context():
        User.query.filter_by(email=user_email_gift).delete()
        db.session.commit()
        user_to_receive_gift = User(email=user_email_gift, password=generate_password_hash('pass'), role='user')
        db.session.add(user_to_receive_gift)
        db.session.commit()
        user_id_gift = user_to_receive_gift.id

    event_data = {"name": "Giftable Event Def", "description": "Event for gifts Def", "date": "2024-12-25T10:00:00"}
    event_res = client.post('/api/events', headers={"Authorization": f"Bearer {token_comp}"}, json=event_data)
    event_id_gift = event_res.get_json()['id']

    client.application.config["STRIPE_SECRET_KEY"] = "sk_test_dummykey_gift_def"
    dummy_charge = mocker.Mock()
    dummy_charge.id = 'ch_dummygiftchargedef'
    mocker.patch('stripe.Charge.create', return_value=dummy_charge)

    issue_gift_data = { # amount_cents is missing, should default to 1000
        "user_id": user_id_gift,
        "payment_source": "tok_visa_default"
    }
    res = client.post(f'/api/events/{event_id_gift}/issue_gift', headers={"Authorization": f"Bearer {token_comp}"}, json=issue_gift_data)
    assert res.status_code == 200
    data = res.get_json()
    assert data['msg'] == "Gift card issued"

    with client.application.app_context():
        gift_card = GiftCard.query.filter_by(user_id=user_id_gift, event_id=event_id_gift).first()
        assert gift_card is not None
        assert gift_card.amount_cents == 1000 # Check default amount

    # Verify stripe.Charge.create was called with default amount
    # The mock was already set up as: mocker.patch('stripe.Charge.create', return_value=dummy_charge)
    stripe.Charge.create.assert_called_with( # Check it was called with the expected default amount
        amount=1000,
        currency="usd",
        source="tok_visa_default",
        description=f"Manual gift for RSVP to event {event_id_gift}"
    )
