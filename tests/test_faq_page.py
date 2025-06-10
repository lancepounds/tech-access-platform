import pytest
from app import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False, SERVER_NAME='localhost.test')
    return app.test_client()

def test_faq_page(client):
    response = client.get('/faq')
    assert response.status_code == 200
    assert b'Frequently Asked Questions' in response.data
