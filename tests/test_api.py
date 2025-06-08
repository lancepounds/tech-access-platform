import pytest
from datetime import datetime
import json
import os
from app import create_app, db
from app.models import Event, User, Company, RSVP, GiftCard
from werkzeug.security import generate_password_hash
import stripe

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
        e1 = Event(id='evt1', title='E1', description='D1', date=datetime(2025,1,1), company_id=None)
        e2 = Event(id='evt2', title='E2', description='D2', date=datetime(2025,2,2), company_id=None)
        db.session.add_all([e1,e2])
        db.session.commit()
    return app.test_client()

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
    client.post('/auth/register', json={'email':'testuser@example.com','password':'password123','role':'user'})
    res = client.post('/auth/api/login', json={'email':'testuser@example.com','password':'password123'})
    assert res.status_code == 200
    data = res.get_json()
    assert 'token' in data and data['role']=='user'

def test_api_login_user_failure(client):
    client.post('/auth/register', json={'email':'testuser2@example.com','password':'password123','role':'user'})
    res = client.post('/auth/api/login', json={'email':'testuser2@example.com','password':'wrongpassword'})
    assert res.status_code == 401
    data = res.get_json()
    assert data.get('error')=='Invalid credentials'

def register_and_login_company(client,name,email,password):
    from app.models import Company
    from werkzeug.security import generate_password_hash
    company = Company(name=name,contact_email=email,password=generate_password_hash(password),approved=True,role='company')
    with client.application.app_context():
        db.session.add(company); db.session.commit(); cid=company.id
    res = client.post('/auth/api/login', json={'email':email,'password':password})
    assert res.status_code==200
    return res.get_json()['token'], cid

def test_create_event_success(client):
    token, cid = register_and_login_company(client,'EventCorp','eventcorp@example.com','securepass123')
    data = {"name":"Tech Conference 2024","description":"Annual tech conference.","date":"2024-12-15T10:00:00"}
    res = client.post('/api/events', headers={"Authorization":f"Bearer {token}"}, json=data)
    assert res.status_code==201
    ev = res.get_json()
    with client.application.app_context():
        e = Event.query.get(ev['id'])
        assert e and e.title==data['name'] and e.company_id==cid

def test_create_event_missing_name(client):
    token,_=register_and_login_company(client,'EventCorpMissing','missing@example.com','pass123')
    data={"description":"Desc only","date":"2024-12-15T10:00:00"}
    res = client.post('/api/events', headers={"Authorization":f"Bearer {token}"}, json=data)
    assert res.status_code==400
    errs=res.get_json()['errors']
    assert 'name' in errs and "Missing data for required field." in errs['name']

def test_create_event_invalid_date_format(client):
    token,_=register_and_login_company(client,'EventCorpDate','date@example.com','pass123')
    data={"name":"A","description":"B","date":"15-12-2024"}
    res = client.post('/api/events', headers={"Authorization":f"Bearer {token}"}, json=data)
    assert res.status_code==400
    errs=res.get_json()['errors']
    assert 'date' in errs

def test_create_event_not_company_role(client):
    client.post('/auth/register', json={'email':'usr@example.com','password':'p','role':'user'})
    lr = client.post('/auth/api/login', json={'email':'usr@example.com','password':'p'})
    token=lr.get_json()['token']
    data={"name":"A","description":"B","date":"2024-12-15T10:00:00"}
    res=client.post('/api/events', headers={"Authorization":f"Bearer {token}"}, json=data)
    assert res.status_code==403

def test_rsvp_notification_sends_to_correct_company_email(client,mocker):
    token_comp,_=register_and_login_company(client,'NotifyCorp','notify@example.com','notifypass')
    ev_data={"name":"NotifyEvt","description":"X","date":"2024-12-20T10:00:00"}
    er=client.post('/api/events', headers={"Authorization":f"Bearer {token_comp}"}, json=ev_data)
    eid=er.get_json()['id']
    client.application.config["STRIPE_SECRET_KEY"]="sk_test"
    dc=mocker.Mock(); dc.id='ch1'; mocker.patch('stripe.Charge.create',return_value=dc)
    me=mocker.patch('app.email_service.send_email')
    rr=client.post(f'/api/events/{eid}/rsvp', headers={"Authorization":f"Bearer {token_comp}"}, json={"payment_source":"tok"})
    assert rr.status_code==201
    me.assert_called_once()
    assert me.call_args[0][0]=='notify@example.com'

def test_rsvp_missing_payment_source(client):
    token_comp,_=register_and_login_company(client,'PayCorp','pay@example.com','pass')
    ev=client.post('/api/events', headers={"Authorization":f"Bearer {token_comp}"}, json={"name":"P","description":"D","date":"2024-12-01T10:00:00"})
    eid=ev.get_json()['id']
    client.post('/auth/register', json={'email':'mem@example.com','password':'p','role':'user'})
    mt=client.post('/auth/api/login', json={'email':'mem@example.com','password':'p'}).get_json()['token']
    rr=client.post(f'/api/events/{eid}/rsvp', headers={"Authorization":f"Bearer {mt}"}, json={})
    assert rr.status_code==400
    with client.application.app_context():
        m=User.query.filter_by(email='mem@example.com').first()
        assert not RSVP.query.filter_by(user_id=m.id,event_id=eid).first()

def test_rsvp_stripe_card_error(client,mocker):
    token_comp,_=register_and_login_company(client,'PayCorp2','pay2@example.com','pass')
    ev=client.post('/api/events', headers={"Authorization":f"Bearer {token_comp}"}, json={"name":"P2","description":"D2","date":"2024-12-02T10:00:00"})
    eid=ev.get_json()['id']
    client.post('/auth/register', json={'email':'mem2@example.com','password':'p','role':'user'})
    mt=client.post('/auth/api/login', json={'email':'mem2@example.com','password':'p'}).get_json()['token']
    client.application.config["STRIPE_SECRET_KEY"]="sk_test"
    import stripe as stripe_module
    mocker.patch('stripe.Charge.create', side_effect=stripe_module.error.CardError("Declined",param="c",code="c"))
    me=mocker.patch('app.email_service.send_email')
    rr=client.post(f'/api/events/{eid}/rsvp', headers={"Authorization":f"Bearer {mt}"}, json={"payment_source":"tok_declined"})
    assert rr.status_code==201
    msg=rr.get_json()['msg']
    assert "failed to process gift card" in msg
    with client.application.app_context():
        m=User.query.filter_by(email='mem2@example.com').first()
        assert RSVP.query.filter_by(user_id=m.id,event_id=eid).first()
        assert not GiftCard.query.filter_by(user_id=m.id,event_id=eid).first()
    me.assert_called_once()

def test_api_login_company_success(client):
    from app.models import Company
    c=Company(name='TC',contact_email='company@example.com',password=generate_password_hash('pw'),approved=True,role='company')
    with client.application.app_context(): db.session.add(c);db.session.commit()
    r=client.post('/auth/api/login', json={'email':'company@example.com','password':'pw'})
    assert r.status_code==200
    d=r.get_json(); assert d['role']=='company' and 'token' in d

def test_api_login_company_failure(client):
    from app.models import Company
    c=Company(name='TC2',contact_email='company2@example.com',password=generate_password_hash('pw'),approved=True,role='company')
    with client.application.app_context(): db.session.add(c);db.session.commit()
    r=client.post('/auth/api/login', json={'email':'company2@example.com','password':'wrong'})
    assert r.status_code==401
    assert r.get_json().get('error')=='Invalid credentials'

def test_issue_gift_success(client,mocker):
    token_comp,_=register_and_login_company(client,'GiftCorp','giftcorp@example.com','giftypass')
    ue='gif@example.com'
    with client.application.app_context():
        User.query.filter_by(email=ue).delete();db.session.commit()
        from werkzeug.security import generate_password_hash
        u=User(email=ue,password=generate_password_hash('p'),role='user');db.session.add(u);db.session.commit(); uid=u.id
    ev=client.post('/api/events', headers={"Authorization":f"Bearer {token_comp}"}, json={"name":"G","description":"G","date":"2024-12-25T10:00:00"})
    eid=ev.get_json()['id']
    client.application.config["STRIPE_SECRET_KEY"]="sk_test"
    dc=mocker.Mock();dc.id='ch_dump';mocker.patch('stripe.Charge.create',return_value=dc)
    res=client.post(f'/api/events/{eid}/issue_gift', headers={"Authorization":f"Bearer {token_comp}"}, json={"user_id":uid,"payment_source":"tok","amount_cents":1500})
    assert res.status_code==200
    d=res.get_json(); assert d['msg']=="Gift card issued" and d['charge_id']==dc.id
    with client.application.app_context(): assert GiftCard.query.filter_by(user_id=uid,event_id=eid).first().amount_cents==1500

def test_issue_gift_missing_user_id(client):
    token_comp,_=register_and_login_company(client,'GiftCorpMU','mu@example.com','gf')
    eid=client.post('/api/events', headers={"Authorization":f"Bearer {token_comp}"}, json={"name":"MU","description":"MU","date":"2024-12-25T10:00:00"}).get_json()['id']
    r=client.post(f'/api/events/{eid}/issue_gift', headers={"Authorization":f"Bearer {token_comp}"}, json={"payment_source":"tok","amount_cents":1500})
    assert r.status_code==400
    errs=r.get_json()['errors']; assert 'user_id' in errs

def test_issue_gift_missing_payment_source(client):
    token_comp,_=register_and_login_company(client,'GiftCorpMP','mp@example.com','gf')
    ue='mp@example.com'
    with client.application.app_context():
        User.query.filter_by(email=ue).delete();db.session.commit()
        from werkzeug.security import generate_password_hash
        u=User(email=ue,password=generate_password_hash('p'),role='user');db.session.add(u);db.session.commit(); uid=u.id
    eid=client.post('/api/events', headers={"Authorization":f"Bearer {token_comp}"}, json={"name":"MP","description":"MP","date":"2024-12-25T10:00:00"}).get_json()['id']
    r=client.post(f'/api/events/{eid}/issue_gift', headers={"Authorization":f"Bearer {token_comp}"}, json={"user_id":uid,"amount_cents":1500})
    assert r.status_code==400
    errs=r.get_json()['errors']; assert 'payment_source' in errs

def test_issue_gift_default_amount(client,mocker):
    token_comp,_=register_and_login_company(client,'GiftCorpDef','def@example.com','gf')
    ue='def@example.com'
    with client.application.app_context():
        User.query.filter_by(email=ue).delete();db.session.commit()
        from werkzeug.security import generate_password_hash
        u=User(email=ue,password=generate_password_hash('p'),role='user');db.session.add(u);db.session.commit(); uid=u.id
    eid=client.post('/api/events', headers={"Authorization":f"Bearer {token_comp}"}, json={"name":"D","description":"D","date":"2024-12-25T10:00:00"}).get_json()['id']
    client.application.config["STRIPE_SECRET_KEY"]="sk_test"
    dc=mocker.Mock();dc.id='ch_def';mocker.patch('stripe.Charge.create',return_value=dc)
    res=client.post(f'/api/events/{eid}/issue_gift', headers={"Authorization":f"Bearer {token_comp}"}, json={"user_id":uid,"payment_source":"tok_default"})
    assert res.status_code==200
    with client.application.app_context():
        g=GiftCard.query.filter_by(user_id=uid,event_id=eid).first(); assert g.amount_cents==1000
    stripe.Charge.create.assert_called_with(amount=1000,currency="usd",source="tok_default",description=f"Manual gift for RSVP to event {eid}")