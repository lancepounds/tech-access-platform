import pytest
from app import create_app, db
from app.models import Company


@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.app_context():
        db.create_all()
        company = Company(name='TechCorp', contact_email='corp@example.com', password='secret', description='Leading tech solutions')
        db.session.add(company)
        db.session.commit()
    yield app.test_client()


def test_company_search_found(client):
    res = client.get('/search/companies?q=TechCorp')
    assert res.status_code == 200
    assert b'TechCorp' in res.data


def test_company_search_no_results(client):
    res = client.get('/search/companies?q=NoMatch')
    assert res.status_code == 200
    assert b'No companies found' in res.data
