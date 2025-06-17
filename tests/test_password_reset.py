import pytest
from flask import url_for, get_flashed_messages
from app.models import User
from app.extensions import db
# from app.email_service import send_email # Not directly used, but app.auth.routes.send_email is patched
from unittest.mock import patch
import datetime

# Test Case 1: Request Password Reset Link
def test_request_password_reset_link_success(test_client, test_user): # Removed capsys, not used
    with patch('app.auth.routes.send_email') as mock_send_email:
        response = test_client.post(url_for('auth.forgot_password'), data={'email': test_user.email})
        assert response.status_code == 302 # Redirects to login
        # Using response.location which is absolute if SERVER_NAME is set
        assert url_for('auth.login') in response.location

        user = User.query.filter_by(email=test_user.email).first()
        assert user.reset_token is not None
        assert user.reset_token_expiration is not None

        mock_send_email.assert_called_once()
        args, kwargs = mock_send_email.call_args
        assert args[0] == test_user.email
        assert args[1] == 'Password Reset Request'
        assert user.reset_token in args[2] # Email HTML content contains the token

def test_request_password_reset_link_unknown_email(test_client, init_database): # Removed capsys
    with patch('app.auth.routes.send_email') as mock_send_email:
        response = test_client.post(url_for('auth.forgot_password'), data={'email': 'nonexistent@example.com'})
        assert response.status_code == 302
        assert url_for('auth.login') in response.location
        mock_send_email.assert_not_called()

# Test Case 2: Access Reset Link with Invalid Token
def test_reset_password_invalid_token(test_client, test_user): # test_user fixture implicitly uses init_database
    # No need for 'with test_client:' block here for get_flashed_messages
    # as test_client itself can manage session context if configured in conftest
    response = test_client.get(url_for('auth.reset_password_with_token', token='invalidtoken'), follow_redirects=True)
    assert response.status_code == 200 # After redirect to forgot_password page
    # Flashed messages are typically checked on the page they are rendered on
    assert b"The password reset link is invalid or has expired." in response.data
    # Check if it redirected to the correct page (content check)
    assert b"Forgot Your Password?" in response.data


# Test Case 3: Access Reset Link with Expired Token
def test_reset_password_expired_token(test_client, test_user):
    token = 'expiredtoken123'
    user = User.query.filter_by(email=test_user.email).first() # Get user from db
    user.reset_token = token
    user.reset_token_expiration = datetime.datetime.utcnow() - datetime.timedelta(hours=2)
    db.session.commit()

    response = test_client.get(url_for('auth.reset_password_with_token', token=token), follow_redirects=True)
    assert response.status_code == 200 # After redirect
    assert b"The password reset link is invalid or has expired." in response.data
    assert b"Forgot Your Password?" in response.data

# Test Case 4: Successful Password Reset
def test_reset_password_success(test_client, test_user):
    # 1. Request reset link
    with patch('app.auth.routes.send_email') as mock_send_email:
        test_client.post(url_for('auth.forgot_password'), data={'email': test_user.email})

        user_from_db = User.query.filter_by(email=test_user.email).first()
        assert user_from_db.reset_token is not None
        token = user_from_db.reset_token

        # 2. Visit reset link (GET)
        response_get = test_client.get(url_for('auth.reset_password_with_token', token=token))
        assert response_get.status_code == 200 # Shows form
        assert b"Reset Your Password" in response_get.data

        # 3. Submit new password (POST)
        new_password = 'newpassword456'
        response_post = test_client.post(url_for('auth.reset_password_with_token', token=token), data={
            'password': new_password,
            'confirm_password': new_password
        }, follow_redirects=True) # follow_redirects to check final page content

        assert response_post.status_code == 200 # Should redirect to login and then show login page
        assert b"Your password has been successfully reset. Please log in." in response_post.data

        updated_user = User.query.filter_by(email=test_user.email).first()
        assert updated_user.reset_token is None
        assert updated_user.reset_token_expiration is None
        assert updated_user.check_password(new_password)
        assert not updated_user.check_password('password123')

        # 4. Try logging in with the new password
        # Attempt login (LoginForm is used by the /login route implicitly)
        login_response = test_client.post(url_for('auth.login'), data={
            'email': test_user.email,
            'password': new_password
        }, follow_redirects=True)
        assert login_response.status_code == 200 # Successful login
        assert b"Logged in successfully" in login_response.data # Or other success indicator from your app's login
        # Depending on where successful login redirects, you might check for dashboard content
        # For example: assert b"Member Dashboard" in login_response.data or url_for('main.show_events') in login_response.request.path
        assert url_for('main.show_events') in login_response.request.path # Assuming successful login redirects here
