import pytest
from datetime import datetime
from app import create_app, db
from app.models import Event, User, Company, RSVP, GiftCard
import json
import os
from werkzeug.security import generate_password_hash
import stripe

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("TEST_DATABASE_URL", "sqlite:///:memory:")
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SECRET_KEY'] = 'test_secret_for_api_v2' # Changed key to ensure freshness
    app.config['SERVER_NAME'] = 'localhost.test'
    app.config['STRIPE_SECRET_KEY'] = "sk_test_dummykey_global" # Global dummy key

    with app.app_context():
        # Clean all tables before creating new ones
        # for table in reversed(db.metadata.sorted_tables):
        #     db.session.execute(table.delete())
        # db.session.commit()
        db.create_all()

        # Minimal initial data, tests should create their own specific data
        e1 = Event(id='evt1', title='E1', description='D1', date=datetime(2025, 1, 1), gift_card_amount_cents=1000) # Default gift card
        e2 = Event(id='evt2', title='E2', description='D2', date=datetime(2025, 2, 2), gift_card_amount_cents=0) # No gift card
        db.session.add_all([e1, e2])
        db.session.commit()
    return app.test_client()

# Helper to register & login company, now includes gift_card_amount for event creation
def register_and_login_company(client, name, email, password):
    with client.application.app_context():
        Company.query.filter((Company.name == name) | (Company.contact_email == email)).delete()
        User.query.filter_by(email=email).delete() # Also clean up potential user with same email
        db.session.commit()

        # Create a User record for the company contact, as login uses the User model
        user_for_company = User(
            email=email,
            password=generate_password_hash(password),
            role='company'
        )
        db.session.add(user_for_company)
        db.session.commit() # Commit user first

        company = Company(
            name=name,
            contact_email=email, # Should match a User email if that user represents the company
            password=generate_password_hash(password), # Company might have its own password for other uses
            approved=True,
            role='company'
        )
        db.session.add(company)
        db.session.commit()
        company_id_val = company.id

    # Login via the User record associated with the company contact_email
    login_res = client.post('/auth/api/login', json={'email': email, 'password': password})
    if login_res.status_code != 200:
        print(f"Company login failed: {login_res.get_data(as_text=True)}")
    assert login_res.status_code == 200
    login_data = login_res.get_json()
    assert 'token' in login_data
    return login_data['token'], company_id_val

# Helper to create an event with specific gift card amount
def create_event_with_gift_amount(client, company_token, name, gift_amount_cents):
    event_data = {
        "name": name,
        "description": f"Event with gift amount {gift_amount_cents}",
        "date": "2024-12-25T10:00:00",
        # Event model now has gift_card_amount_cents, but create_event API schema doesn't take it.
        # This needs to be set when the event is created server-side, or the event model needs default.
        # For testing, we'll assume the event is created and then updated with this amount if needed,
        # OR, the create_event logic should be modified to accept it.
        # For now, we will create event then update it in DB for test setup.
    }
    res = client.post('/api/events', headers={"Authorization": f"Bearer {company_token}"}, json=event_data)
    assert res.status_code == 201
    event_id = res.get_json()['id']
    with client.application.app_context():
        event = db.session.get(Event, event_id)
        assert event is not None
        event.gift_card_amount_cents = gift_amount_cents # Manually set for test
        db.session.commit()
    return event_id


# --- Existing Tests (some may need minor tweaks) ---
def test_list_events(client):
    res = client.get('/api/events')
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)
    assert any(evt['title']=='E1' for evt in data)

def test_get_event(client):
    res = client.get('/api/events/evt1')
    assert res.status_code == 404

def test_event_not_found(client):
    res = client.get('/api/events/evt_nonexistent')
    assert res.status_code == 404

def test_api_login_user_success(client):
    email = 'testuser_api_login_gift@example.com'
    with client.application.app_context(): User.query.filter_by(email=email).delete(); db.session.commit()
    client.post('/auth/register', json={'email': email, 'password': 'password123', 'role': 'user'})
    res = client.post('/auth/api/login', json={'email': email, 'password': 'password123'})
    assert res.status_code == 200
    data = res.get_json(); assert 'token' in data; assert data['role'] == 'user'

def test_api_login_user_failure(client):
    email = 'testuser2_api_login_gift@example.com'
    with client.application.app_context(): User.query.filter_by(email=email).delete(); db.session.commit()
    client.post('/auth/register', json={'email': email, 'password': 'password123', 'role': 'user'})
    res = client.post('/auth/api/login', json={'email': email, 'password': 'wrongpassword'})
    assert res.status_code == 401; assert 'error' in res.get_json()

def test_create_event_success(client):
    token, company_id = register_and_login_company(client, 'EventCorpGift', 'eventcorp_api_gift@example.com', 'securepass123')
    event_data = {"name": "Tech Conference Gift", "description": "Annual tech conference with gift.", "date": "2024-12-15T10:00:00"}
    res = client.post('/api/events', headers={"Authorization": f"Bearer {token}"}, json=event_data)
    assert res.status_code == 201
    data = res.get_json(); assert 'id' in data
    with client.application.app_context():
        event = db.session.get(Event, data['id']); assert event is not None; assert event.title == event_data['name']
        assert event.company_id == company_id
        assert event.gift_card_amount_cents == 1000 # Check default if not provided by API yet

# ... (other create_event tests for missing fields, invalid date, role check - should be fine) ...
def test_create_event_missing_name(client):
    token, _ = register_and_login_company(client, 'EventCorpMissingGift', 'eventcorpmissing_api_gift@example.com', 'securepass123')
    event_data = {"description": "Annual tech conference.","date": "2024-12-15T10:00:00"}
    res = client.post('/api/events', headers={"Authorization": f"Bearer {token}"}, json=event_data)
    assert res.status_code == 400; data = res.get_json(); assert 'errors' in data; assert 'name' in data['errors']

def test_create_event_missing_description(client):
    token, _ = register_and_login_company(client, 'EventCorpDescGift', 'eventcorpdesc_api_gift@example.com', 'securepass123')
    event_data = {"name": "No Description Event Gift","date": "2024-12-15T10:00:00"}
    res = client.post('/api/events', headers={"Authorization": f"Bearer {token}"}, json=event_data)
    assert res.status_code == 400; data = res.get_json(); assert 'errors' in data; assert 'description' in data['errors']

def test_create_event_missing_date(client):
    token, _ = register_and_login_company(client, 'EventCorpDateGift', 'eventcorpdate_api_gift@example.com', 'securepass123')
    event_data = {"name": "No Date Event Gift","description": "This event has no date."}
    res = client.post('/api/events', headers={"Authorization": f"Bearer {token}"}, json=event_data)
    assert res.status_code == 400; data = res.get_json(); assert 'errors' in data; assert 'date' in data['errors']

def test_create_event_invalid_date_format(client):
    token, _ = register_and_login_company(client, 'EventCorpDateFmtGift', 'eventcorpdatefmt_api_gift@example.com', 'securepass123')
    event_data = {"name": "Tech Conference Gift DateFmt","description": "Annual tech conference.","date": "15-12-2024" }
    res = client.post('/api/events', headers={"Authorization": f"Bearer {token}"}, json=event_data)
    assert res.status_code == 400; data = res.get_json(); assert 'errors' in data; assert 'date' in data['errors']

def test_create_event_not_company_role(client):
    email = 'notacompany_api_gift@example.com'
    with client.application.app_context(): User.query.filter_by(email=email).delete(); db.session.commit()
    client.post('/auth/register', json={'email': email, 'password': 'password123', 'role': 'user'})
    login_res = client.post('/auth/api/login', json={'email': email, 'password': 'password123'})
    token = login_res.get_json()['token']
    event_data = {"name": "Tech Conf Gift Role","description": "Annual.","date": "2024-12-15T10:00:00"}
    res = client.post('/api/events', headers={"Authorization": f"Bearer {token}"}, json=event_data)
    assert res.status_code == 403

# --- Updated and New RSVP Tests ---
def test_rsvp_event_with_specific_gift_amount(client, mocker):
    token_comp, _ = register_and_login_company(client, 'GiftAmountCorp', 'giftamount_api@example.com', 'pass123')
    event_id = create_event_with_gift_amount(client, token_comp, "Specific Gift Event", 500) # 500 cents

    member_email = 'member_specificgift_api@example.com'
    with client.application.app_context(): User.query.filter_by(email=member_email).delete(); db.session.commit()
    client.post('/auth/register', json={'email': member_email, 'password': 'password123', 'role': 'user'})
    member_login_res = client.post('/auth/api/login', json={'email': member_email, 'password': 'password123'})
    member_token = member_login_res.get_json()['token']

    mock_stripe_charge = mocker.patch('stripe.Charge.create')
    mock_stripe_charge.return_value.id = 'ch_specificamount'
    mocker.patch('app.email_service.send_email')

    rsvp_data = {"payment_source": "tok_visa_specific"}
    res = client.post(f'/api/events/{event_id}/rsvp', headers={"Authorization": f"Bearer {member_token}"}, json=rsvp_data)
    assert res.status_code == 201
    data = res.get_json()
    assert "and a gift card for $5.00 was issued" in data['msg']
    stripe.Charge.create.assert_called_once_with(amount=500, currency="usd", source="tok_visa_specific", description=f"Gift card for RSVP to event {event_id}")
    with client.application.app_context():
        user = User.query.filter_by(email=member_email).first()
        gift_card = GiftCard.query.filter_by(user_id=user.id, event_id=event_id).first()
        assert gift_card is not None
        assert gift_card.amount_cents == 500

def test_rsvp_event_with_zero_gift_amount(client, mocker):
    token_comp, _ = register_and_login_company(client, 'ZeroGiftCorp', 'zerogift_api@example.com', 'pass123')
    event_id = create_event_with_gift_amount(client, token_comp, "Zero Gift Event", 0)

    member_email = 'member_zerogift_api@example.com'
    with client.application.app_context(): User.query.filter_by(email=member_email).delete(); db.session.commit()
    client.post('/auth/register', json={'email': member_email, 'password': 'password123', 'role': 'user'})
    member_login_res = client.post('/auth/api/login', json={'email': member_email, 'password': 'password123'})
    member_token = member_login_res.get_json()['token']

    mock_stripe_charge = mocker.patch('stripe.Charge.create')
    mocker.patch('app.email_service.send_email')

    rsvp_data = {"payment_source": "tok_visa_zero"}
    res = client.post(f'/api/events/{event_id}/rsvp', headers={"Authorization": f"Bearer {member_token}"}, json=rsvp_data)
    assert res.status_code == 201
    data = res.get_json()
    assert "and no gift card was offered for this event" in data['msg']
    mock_stripe_charge.assert_not_called()
    with client.application.app_context():
        user = User.query.filter_by(email=member_email).first()
        gift_card = GiftCard.query.filter_by(user_id=user.id, event_id=event_id).first()
        assert gift_card is None

def test_rsvp_event_with_null_gift_amount(client, mocker):
    token_comp, _ = register_and_login_company(client, 'NullGiftCorp', 'nullgift_api@example.com', 'pass123')
    event_id = create_event_with_gift_amount(client, token_comp, "Null Gift Event", None)

    member_email = 'member_nullgift_api@example.com'
    with client.application.app_context(): User.query.filter_by(email=member_email).delete(); db.session.commit()
    client.post('/auth/register', json={'email': member_email, 'password': 'password123', 'role': 'user'})
    member_login_res = client.post('/auth/api/login', json={'email': member_email, 'password': 'password123'})
    member_token = member_login_res.get_json()['token']

    mock_stripe_charge = mocker.patch('stripe.Charge.create')
    mocker.patch('app.email_service.send_email')

    rsvp_data = {"payment_source": "tok_visa_null"}
    res = client.post(f'/api/events/{event_id}/rsvp', headers={"Authorization": f"Bearer {member_token}"}, json=rsvp_data)
    assert res.status_code == 201
    data = res.get_json()
    assert "and no gift card was offered for this event" in data['msg']
    mock_stripe_charge.assert_not_called()
    with client.application.app_context():
        user = User.query.filter_by(email=member_email).first()
        gift_card = GiftCard.query.filter_by(user_id=user.id, event_id=event_id).first()
        assert gift_card is None

def test_rsvp_stripe_card_error_with_dynamic_amount(client, mocker): # Updated test
    token_comp, _ = register_and_login_company(client, 'PaymentCorpDyn', 'payment_dyn_api@example.com', 'pass123')
    event_id = create_event_with_gift_amount(client, token_comp, "Payment Test Event Dyn", 750) # 750 cents

    member_email = 'member_paymentdyn_api@example.com'
    with client.application.app_context(): User.query.filter_by(email=member_email).delete(); db.session.commit()
    client.post('/auth/register', json={'email': member_email, 'password': 'password123', 'role': 'user'})
    member_login_res = client.post('/auth/api/login', json={'email': member_email, 'password': 'password123'})
    member_token = member_login_res.get_json()['token']

    client.application.config["STRIPE_SECRET_KEY"] = "sk_test_dummykey"
    mocker.patch('stripe.Charge.create', side_effect=stripe.error.CardError("Your card was declined.", param="card_error", code="card_declined"))
    mock_send_email = mocker.patch('app.email_service.send_email')

    rsvp_data = {"payment_source": "tok_visa_declined_dyn"}
    res = client.post(f'/api/events/{event_id}/rsvp', headers={"Authorization": f"Bearer {member_token}"}, json=rsvp_data)
    assert res.status_code == 201
    data = res.get_json()
    assert "RSVP confirmed" in data['msg']
    assert "but failed to process gift card: Your card was declined." in data['msg']

    stripe.Charge.create.assert_called_once_with(amount=750, currency="usd", source="tok_visa_declined_dyn", description=f"Gift card for RSVP to event {event_id}")
    with client.application.app_context():
        member = User.query.filter_by(email=member_email).first()
        rsvp_record = RSVP.query.filter_by(user_id=member.id, event_id=event_id).first()
        assert rsvp_record is not None
        gift_card_record = GiftCard.query.filter_by(user_id=member.id, event_id=event_id).first()
        assert gift_card_record is None
    mock_send_email.assert_called_once()


# Test for RSVP notification email recipient (adapted from existing)
def test_rsvp_notification_sends_to_correct_company_email(client, mocker): # Keep this, ensure event has gift amount
    token_comp, company_id = register_and_login_company(client, 'NotifyCorpGift', 'notify_api_gift@example.com', 'notifypass')
    event_id = create_event_with_gift_amount(client, token_comp, "Notification Test Event Gift", 1200) # 1200 cents

    member_email = 'member_rsvp_notify_api@example.com'
    with client.application.app_context(): User.query.filter_by(email=member_email).delete(); db.session.commit()
    client.post('/auth/register', json={'email': member_email, 'password': 'password123', 'role': 'user'})
    member_login_res = client.post('/auth/api/login', json={'email': member_email, 'password': 'password123'})
    member_token = member_login_res.get_json()['token']

    client.application.config["STRIPE_SECRET_KEY"] = "sk_test_dummykey"
    dummy_charge = mocker.Mock()
    dummy_charge.id = 'ch_dummychargeid_notify'
    mocker.patch('stripe.Charge.create', return_value=dummy_charge)
    mock_send_email = mocker.patch('app.email_service.send_email')

    rsvp_data = {"payment_source": "tok_visa_notify"}
    rsvp_res = client.post(f'/api/events/{event_id}/rsvp', headers={"Authorization": f"Bearer {member_token}"}, json=rsvp_data)
    assert rsvp_res.status_code == 201
    assert "and a gift card for $12.00 was issued" in rsvp_res.get_json()['msg']

    mock_send_email.assert_called_once()
    args, _ = mock_send_email.call_args
    assert args[0] == 'notify_api_gift@example.com'
    stripe.Charge.create.assert_called_once_with(amount=1200, currency="usd", source="tok_visa_notify", description=f"Gift card for RSVP to event {event_id}")


def test_rsvp_missing_payment_source(client): # This test is fine, schema handles it
    token_comp, _ = register_and_login_company(client, 'PaymentCorp1Gift', 'payment1_api_gift@example.com', 'pass123')
    event_id = create_event_with_gift_amount(client, token_comp, "Payment Test Event 1 Gift", 1000) # Has gift amount

    member_email = 'member_payment1_api_gift@example.com'
    with client.application.app_context(): User.query.filter_by(email=member_email).delete(); db.session.commit()
    client.post('/auth/register', json={'email': member_email, 'password': 'password123', 'role': 'user'})
    member_login_res = client.post('/auth/api/login', json={'email': member_email, 'password': 'password123'})
    member_token = member_login_res.get_json()['token']

    rsvp_res = client.post(f'/api/events/{event_id}/rsvp', headers={"Authorization": f"Bearer {member_token}"}, json={})
    assert rsvp_res.status_code == 400
    data = rsvp_res.get_json()
    assert 'errors' in data; assert 'payment_source' in data['errors']

# --- Other existing tests ---
def test_api_login_company_success(client):
    company_email = 'company_api_login_gift@example.com'
    with client.application.app_context(): Company.query.filter_by(contact_email=company_email).delete(); db.session.commit()
    company = Company(name='TestCompanyAPIGift', contact_email=company_email, password=generate_password_hash('companypassword'), approved=True, role='company')
    with client.application.app_context(): db.session.add(company); db.session.commit()
    res = client.post('/auth/api/login', json={'email': company_email, 'password': 'companypassword'})
    assert res.status_code == 200; data = res.get_json(); assert 'token' in data; assert data['role'] == 'company'

def test_api_login_company_failure(client):
    company_email = 'company2_api_login_gift@example.com'
    with client.application.app_context(): Company.query.filter_by(contact_email=company_email).delete(); db.session.commit()
    company = Company(name='TestCompany2APIGift', contact_email=company_email, password=generate_password_hash('companypassword'), approved=True, role='company')
    with client.application.app_context(): db.session.add(company); db.session.commit()
    res = client.post('/auth/api/login', json={'email': company_email, 'password': 'wrongcompanypassword'})
    assert res.status_code == 401; assert 'error' in res.get_json()

# --- Tests for issue_gift (mostly unchanged as it uses schema default/input) ---
def test_issue_gift_success(client, mocker):
    token_comp, company_id = register_and_login_company(client, 'GiftCorpIssue', 'giftcorp_issue_api@example.com', 'giftypass')
    user_email_gift = 'giftee_issue_api@example.com'
    with client.application.app_context(): User.query.filter_by(email=user_email_gift).delete(); db.session.commit()
    user_to_receive_gift = User(email=user_email_gift, password=generate_password_hash('pass'), role='user')
    with client.application.app_context(): db.session.add(user_to_receive_gift); db.session.commit(); user_id_gift = user_to_receive_gift.id

    event_id_gift = create_event_with_gift_amount(client, token_comp, "Giftable Event Issue", 500) # Event has its own amount

    client.application.config["STRIPE_SECRET_KEY"] = "sk_test_dummykey_gift_issue"
    dummy_charge = mocker.Mock(); dummy_charge.id = 'ch_dummygiftchargeissue'
    mocker.patch('stripe.Charge.create', return_value=dummy_charge)

    issue_gift_data = {"user_id": user_id_gift, "payment_source": "tok_mastercard", "amount_cents": 1500 }
    res = client.post(f'/api/events/{event_id_gift}/issue_gift', headers={"Authorization": f"Bearer {token_comp}"}, json=issue_gift_data)
    assert res.status_code == 200; data = res.get_json(); assert data['msg'] == "Gift card issued"
    stripe.Charge.create.assert_called_once_with(amount=1500, currency="usd", source="tok_mastercard", description=f"Manual gift for RSVP to event {event_id_gift}")
    with client.application.app_context():
        gift_card = GiftCard.query.filter_by(user_id=user_id_gift, event_id=event_id_gift, amount_cents=1500).first()
        assert gift_card is not None

def test_issue_gift_missing_user_id(client):
    token_comp, _ = register_and_login_company(client, 'GiftCorpMissUserIssue', 'giftcorpmu_issue_api@example.com', 'giftypass')
    event_id_gift = create_event_with_gift_amount(client, token_comp, "Giftable Event MUIssue", None)
    issue_gift_data = {"payment_source": "tok_mastercard", "amount_cents": 1500 }
    res = client.post(f'/api/events/{event_id_gift}/issue_gift', headers={"Authorization": f"Bearer {token_comp}"}, json=issue_gift_data)
    assert res.status_code == 400; data = res.get_json(); assert 'errors' in data; assert 'user_id' in data['errors']

def test_issue_gift_missing_payment_source(client):
    token_comp, _ = register_and_login_company(client, 'GiftCorpMissPayIssue', 'giftcorpmps_issue_api@example.com', 'giftypass')
    user_email_gift = 'gifteemps_issue_api@example.com'
    with client.application.app_context(): User.query.filter_by(email=user_email_gift).delete(); db.session.commit()
    user_to_receive_gift = User(email=user_email_gift, password=generate_password_hash('pass'), role='user')
    with client.application.app_context(): db.session.add(user_to_receive_gift); db.session.commit(); user_id_gift = user_to_receive_gift.id
    event_id_gift = create_event_with_gift_amount(client, token_comp, "Giftable Event MPSIssue", 0)
    issue_gift_data = {"user_id": user_id_gift, "amount_cents": 1500 }
    res = client.post(f'/api/events/{event_id_gift}/issue_gift', headers={"Authorization": f"Bearer {token_comp}"}, json=issue_gift_data)
    assert res.status_code == 400; data = res.get_json(); assert 'errors' in data; assert 'payment_source' in data['errors']

def test_issue_gift_default_amount(client, mocker):
    token_comp, company_id = register_and_login_company(client, 'GiftCorpDefIssue', 'giftcorpdef_issue_api@example.com', 'giftypass')
    user_email_gift = 'gifteedef_issue_api@example.com'
    with client.application.app_context(): User.query.filter_by(email=user_email_gift).delete(); db.session.commit()
    user_to_receive_gift = User(email=user_email_gift, password=generate_password_hash('pass'), role='user')
    with client.application.app_context(): db.session.add(user_to_receive_gift); db.session.commit(); user_id_gift = user_to_receive_gift.id
    event_id_gift = create_event_with_gift_amount(client, token_comp, "Giftable Event DefIssue", 2000) # Event has its own amount

    client.application.config["STRIPE_SECRET_KEY"] = "sk_test_dummykey_gift_def_issue"
    dummy_charge = mocker.Mock(); dummy_charge.id = 'ch_dummygiftchargedefissue'
    mocker.patch('stripe.Charge.create', return_value=dummy_charge)

    issue_gift_data = {"user_id": user_id_gift, "payment_source": "tok_visa_default_issue"} # amount_cents missing
    res = client.post(f'/api/events/{event_id_gift}/issue_gift', headers={"Authorization": f"Bearer {token_comp}"}, json=issue_gift_data)
    assert res.status_code == 200; data = res.get_json(); assert data['msg'] == "Gift card issued"
    stripe.Charge.create.assert_called_with(amount=1000, currency="usd", source="tok_visa_default_issue", description=f"Manual gift for RSVP to event {event_id_gift}") # Default is 1000 from schema
    with client.application.app_context():
        gift_card = GiftCard.query.filter_by(user_id=user_id_gift, event_id=event_id_gift, amount_cents=1000).first()
        assert gift_card is not None
