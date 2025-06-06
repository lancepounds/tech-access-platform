
import time

import requests

from app.models import CheckResult


def run_check(check):
    """
    Execute a health check by sending HTTP GET request to the target URL.
    
    Args:
        check: Check SQLAlchemy object with target URL and other properties
        
    Returns:
        CheckResult: New CheckResult object (not committed to database)
    """
    start_time = time.time()
    status = 'down'
    latency_ms = 0
    
    try:
        # Send HTTP GET request with 5-second timeout
        response = requests.get(
            check.target,
            timeout=5.0,
            headers={
                'User-Agent': 'HealthCheck/1.0'
            },
            allow_redirects=True
        )
        
        # Calculate latency in milliseconds
        end_time = time.time()
        latency_ms = int((end_time - start_time) * 1000)
        
        # Determine status based on response code
        status = 'up' if 200 <= response.status_code <= 399 else 'down'
            
    except requests.exceptions.Timeout:
        # Handle timeout (5+ seconds)
        end_time = time.time()
        latency_ms = int((end_time - start_time) * 1000)
        status = 'down'
        
    except requests.exceptions.RequestException:
        # Handle all other request exceptions (DNS, connection, invalid URL, etc.)
        end_time = time.time()
        latency_ms = int((end_time - start_time) * 1000)
        status = 'down'
        
    except Exception:
        # Handle any other unexpected exceptions
        end_time = time.time()
        latency_ms = int((end_time - start_time) * 1000)
        status = 'down'
    
    # Create and return CheckResult object (not committed)
    return CheckResult(
        check_id=check.id,
        status=status,
        latency_ms=latency_ms
    )
