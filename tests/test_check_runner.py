
import pytest
import time
from unittest.mock import Mock, patch
import requests
from app.checks.runner import run_check
from app.models import Check, CheckResult


class TestRunCheck:
    """Test cases for the run_check function."""
    
    def setup_method(self):
        """Set up test data for each test."""
        self.mock_check = Mock()
        self.mock_check.id = 1
        self.mock_check.target = "https://example.com"
    
    @patch('app.checks.runner.requests.get')
    def test_successful_request_status_up(self, mock_get):
        """Test successful request with 2xx status code."""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        result = run_check(self.mock_check)
        
        # Verify request was made correctly
        mock_get.assert_called_once_with(
            self.mock_check.target,
            timeout=5.0,
            headers={'User-Agent': 'HealthCheck/1.0'},
            allow_redirects=True
        )
        
        # Verify result
        assert isinstance(result, CheckResult)
        assert result.check_id == self.mock_check.id
        assert result.status == 'up'
        assert result.latency_ms >= 0
    
    @patch('app.checks.runner.requests.get')
    def test_3xx_status_code_up(self, mock_get):
        """Test 3xx status codes are considered 'up'."""
        mock_response = Mock()
        mock_response.status_code = 302
        mock_get.return_value = mock_response
        
        result = run_check(self.mock_check)
        
        assert result.status == 'up'
        assert result.check_id == self.mock_check.id
    
    @patch('app.checks.runner.requests.get')
    def test_4xx_status_code_down(self, mock_get):
        """Test 4xx status codes are considered 'down'."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        result = run_check(self.mock_check)
        
        assert result.status == 'down'
        assert result.check_id == self.mock_check.id
        assert result.latency_ms >= 0
    
    @patch('app.checks.runner.requests.get')
    def test_5xx_status_code_down(self, mock_get):
        """Test 5xx status codes are considered 'down'."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response
        
        result = run_check(self.mock_check)
        
        assert result.status == 'down'
        assert result.check_id == self.mock_check.id
        assert result.latency_ms >= 0
    
    @patch('app.checks.runner.requests.get')
    def test_timeout_handling(self, mock_get):
        """Test timeout exception handling."""
        mock_get.side_effect = requests.exceptions.Timeout()
        
        result = run_check(self.mock_check)
        
        assert result.status == 'down'
        assert result.check_id == self.mock_check.id
        assert result.latency_ms >= 0
        
        # Verify timeout was used
        mock_get.assert_called_once_with(
            self.mock_check.target,
            timeout=5.0,
            headers={'User-Agent': 'HealthCheck/1.0'},
            allow_redirects=True
        )
    
    @patch('app.checks.runner.requests.get')
    def test_connection_error_handling(self, mock_get):
        """Test connection error handling."""
        mock_get.side_effect = requests.exceptions.ConnectionError()
        
        result = run_check(self.mock_check)
        
        assert result.status == 'down'
        assert result.check_id == self.mock_check.id
        assert result.latency_ms >= 0
    
    @patch('app.checks.runner.requests.get')
    def test_invalid_url_handling(self, mock_get):
        """Test invalid URL handling."""
        mock_get.side_effect = requests.exceptions.InvalidURL()
        
        result = run_check(self.mock_check)
        
        assert result.status == 'down'
        assert result.check_id == self.mock_check.id
        assert result.latency_ms >= 0
    
    @patch('app.checks.runner.requests.get')
    def test_dns_resolution_error(self, mock_get):
        """Test DNS resolution error handling."""
        mock_get.side_effect = requests.exceptions.ConnectTimeout()
        
        result = run_check(self.mock_check)
        
        assert result.status == 'down'
        assert result.check_id == self.mock_check.id
        assert result.latency_ms >= 0
    
    @patch('app.checks.runner.requests.get')
    def test_generic_request_exception(self, mock_get):
        """Test generic RequestException handling."""
        mock_get.side_effect = requests.exceptions.RequestException("Generic error")
        
        result = run_check(self.mock_check)
        
        assert result.status == 'down'
        assert result.check_id == self.mock_check.id
        assert result.latency_ms >= 0
    
    @patch('app.checks.runner.requests.get')
    def test_unexpected_exception(self, mock_get):
        """Test handling of unexpected exceptions."""
        mock_get.side_effect = ValueError("Unexpected error")
        
        result = run_check(self.mock_check)
        
        assert result.status == 'down'
        assert result.check_id == self.mock_check.id
        assert result.latency_ms >= 0
    
    @patch('app.checks.runner.requests.get')
    @patch('app.checks.runner.time.time')
    def test_latency_measurement(self, mock_time, mock_get):
        """Test accurate latency measurement."""
        # Mock time progression
        mock_time.side_effect = [1000.0, 1000.5]  # 500ms difference
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        result = run_check(self.mock_check)
        
        assert result.latency_ms == 500
        assert result.status == 'up'
    
    @patch('app.checks.runner.requests.get')
    def test_user_agent_header(self, mock_get):
        """Test that correct User-Agent header is sent."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        run_check(self.mock_check)
        
        mock_get.assert_called_once_with(
            self.mock_check.target,
            timeout=5.0,
            headers={'User-Agent': 'HealthCheck/1.0'},
            allow_redirects=True
        )
    
    @patch('app.checks.runner.requests.get')
    def test_redirects_allowed(self, mock_get):
        """Test that redirects are followed."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        run_check(self.mock_check)
        
        # Verify allow_redirects=True was passed
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs['allow_redirects'] is True
    
    def test_check_result_attributes(self):
        """Test that CheckResult object has all required attributes."""
        with patch('app.checks.runner.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            result = run_check(self.mock_check)
            
            # Verify all required attributes are present
            assert hasattr(result, 'check_id')
            assert hasattr(result, 'status')
            assert hasattr(result, 'latency_ms')
            assert result.check_id == self.mock_check.id
            assert result.status in ['up', 'down']
            assert isinstance(result.latency_ms, int)
            assert result.latency_ms >= 0


class TestStatusCodeRanges:
    """Test status code edge cases and ranges."""
    
    def setup_method(self):
        """Set up test data."""
        self.mock_check = Mock()
        self.mock_check.id = 1
        self.mock_check.target = "https://example.com"
    
    @pytest.mark.parametrize("status_code,expected_status", [
        (200, 'up'),    # OK
        (201, 'up'),    # Created
        (299, 'up'),    # Edge of 2xx
        (300, 'up'),    # Multiple Choices
        (301, 'up'),    # Moved Permanently
        (399, 'up'),    # Edge of 3xx
        (400, 'down'),  # Bad Request
        (401, 'down'),  # Unauthorized
        (404, 'down'),  # Not Found
        (499, 'down'),  # Edge of 4xx
        (500, 'down'),  # Internal Server Error
        (503, 'down'),  # Service Unavailable
        (599, 'down'),  # Edge of 5xx
        (100, 'down'),  # Below 200
        (199, 'down'),  # Edge below 200
        (600, 'down'),  # Above 5xx
    ])
    @patch('app.checks.runner.requests.get')
    def test_status_code_ranges(self, mock_get, status_code, expected_status):
        """Test various HTTP status codes and their expected results."""
        mock_response = Mock()
        mock_response.status_code = status_code
        mock_get.return_value = mock_response
        
        result = run_check(self.mock_check)
        
        assert result.status == expected_status
        assert result.check_id == self.mock_check.id
        assert isinstance(result.latency_ms, int)
        assert result.latency_ms >= 0
