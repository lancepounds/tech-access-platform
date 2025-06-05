
#!/usr/bin/env python3
"""
Quick API test script for immediate endpoint testing.
"""

import requests
import json
import pytest

pytest.skip("helper script", allow_module_level=True)

BASE_URL = "http://0.0.0.0:5000"

def test_endpoint(method, endpoint, data=None, headers=None):
    """Test a single endpoint"""
    url = f"{BASE_URL}{endpoint}"
    
    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers)
        elif method.upper() == "POST":
            response = requests.post(url, json=data, headers=headers)
        elif method.upper() == "PUT":
            response = requests.put(url, json=data, headers=headers)
        elif method.upper() == "DELETE":
            response = requests.delete(url, headers=headers)
        
        print(f"\n{method.upper()} {endpoint}")
        print(f"Status: {response.status_code}")
        print(f"Headers: {dict(response.headers)}")
        
        try:
            content = response.json()
            print(f"JSON Response: {json.dumps(content, indent=2)}")
        except:
            print(f"Text Response: {response.text[:500]}...")
            
    except Exception as e:
        print(f"Error testing {endpoint}: {str(e)}")

if __name__ == "__main__":
    print("Quick API Tests")
    print("=" * 40)
    
    # Test basic endpoints
    test_endpoint("GET", "/")
    test_endpoint("GET", "/_db_health")
    test_endpoint("GET", "/events-page")
    test_endpoint("GET", "/auth/login")
    
    # Test registration
    test_endpoint("POST", "/auth/register", {
        "email": "quicktest@example.com",
        "password": "password123",
        "role": "user"
    })
    
    # Test login
    test_endpoint("POST", "/auth/login", {
        "email": "quicktest@example.com", 
        "password": "password123"
    })
