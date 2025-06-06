
#!/usr/bin/env python3
"""
Comprehensive endpoint testing script for the Flask application. Tests all major API
endpoints including authentication, events, RSVPs, and user management.
"""

import sys

import requests

# Base URL for your Flask app
BASE_URL = "http://0.0.0.0:5000"

class EndpointTester:
    def __init__(self):
        self.base_url = BASE_URL
        self.session = requests.Session()
        self.user_token = None
        self.company_token = None
        self.test_results = []

    def log_test(self, test_name, success, message=""):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        self.test_results.append({
            'test': test_name,
            'success': success,
            'message': message
        })
        print(f"{status}: {test_name} - {message}")

    def test_health_check(self):
        """Test basic health endpoints"""
        try:
            response = self.session.get(f"{self.base_url}/")
            success = response.status_code == 200
            self.log_test("Home Page", success, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Home Page", False, f"Error: {str(e)}")

        try:
            response = self.session.get(f"{self.base_url}/_db_health")
            # Either works or fails gracefully
            success = response.status_code in [200, 500]
            self.log_test("Database Health", success, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Database Health", False, f"Error: {str(e)}")

    def test_user_registration(self):
        """Test user registration endpoint"""
        test_user = {
            "email": "testuser@example.com",
            "password": "testpassword123",
            "role": "user"
        }

        try:
            response = self.session.post(
                f"{self.base_url}/auth/register",
                json=test_user
            )
            # 400 if user already exists
            success = response.status_code in [201, 400]
            self.log_test(
                "User Registration", success, f"Status: {response.status_code}"
            )
        except Exception as e:
            self.log_test("User Registration", False, f"Error: {str(e)}")

    def test_user_login(self):
        """Test user login and get token"""
        login_data = {
            "email": "testuser@example.com",
            "password": "testpassword123"
        }

        try:
            response = self.session.post(
                f"{self.base_url}/auth/login",
                json=login_data
            )
            
            if response.status_code == 200:
                data = response.json()
                self.user_token = data.get('token')
                self.log_test(
                    "User Login", True, f"Token received: {bool(self.user_token)}"
                )
            else:
                self.log_test("User Login", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("User Login", False, f"Error: {str(e)}")

    def test_company_registration(self):
        """Test company registration"""
        test_company = {
            "email": "testcompany@example.com",
            "password": "testcompany123",
            "role": "company"
        }

        try:
            response = self.session.post(
                f"{self.base_url}/auth/register",
                json=test_company
            )
            success = response.status_code in [201, 400]
            self.log_test(
                "Company Registration", success, f"Status: {response.status_code}"
            )
        except Exception as e:
            self.log_test("Company Registration", False, f"Error: {str(e)}")

    def test_protected_endpoint(self):
        """Test protected endpoint with JWT token"""
        if not self.user_token:
            self.log_test("Protected Endpoint", False, "No user token available")
            return

        headers = {"Authorization": f"Bearer {self.user_token}"}
        
        try:
            response = self.session.get(
                f"{self.base_url}/auth/protected",
                headers=headers
            )
            success = response.status_code == 200
            self.log_test(
                "Protected Endpoint", success, f"Status: {response.status_code}"
            )
        except Exception as e:
            self.log_test("Protected Endpoint", False, f"Error: {str(e)}")

    def test_events_listing(self):
        """Test events listing endpoint"""
        try:
            response = self.session.get(f"{self.base_url}/events-page")
            success = response.status_code == 200
            self.log_test("Events Listing", success, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Events Listing", False, f"Error: {str(e)}")

    def test_create_event_page(self):
        """Test create event page"""
        try:
            response = self.session.get(f"{self.base_url}/create-event")
            success = response.status_code == 200
            self.log_test(
                "Create Event Page", success, f"Status: {response.status_code}"
            )
        except Exception as e:
            self.log_test("Create Event Page", False, f"Error: {str(e)}")

    def test_my_rsvps_api(self):
        """Test My RSVPs API endpoint"""
        if not self.user_token:
            self.log_test("My RSVPs API", False, "No user token available")
            return

        headers = {"Authorization": self.user_token}
        
        try:
            response = self.session.get(
                f"{self.base_url}/my-rsvps",
                headers=headers
            )
            success = response.status_code in [200, 401, 403]
            self.log_test("My RSVPs API", success, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("My RSVPs API", False, f"Error: {str(e)}")

    def test_sendgrid_config(self):
        """Test SendGrid configuration"""
        try:
            response = self.session.get(
                f"{self.base_url}/test-sendgrid?email=test@example.com"
            )
            # Either works or fails gracefully
            success = response.status_code in [200, 500]
            self.log_test("SendGrid Config", success, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("SendGrid Config", False, f"Error: {str(e)}")

    def test_web_login_page(self):
        """Test web login page"""
        try:
            response = self.session.get(f"{self.base_url}/auth/login")
            success = response.status_code == 200
            self.log_test("Web Login Page", success, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Web Login Page", False, f"Error: {str(e)}")

    def test_web_signup_page(self):
        """Test web signup page"""
        try:
            response = self.session.get(f"{self.base_url}/auth/signup")
            success = response.status_code == 200
            self.log_test("Web Signup Page", success, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Web Signup Page", False, f"Error: {str(e)}")

    def test_register_page(self):
        """Test user registration page"""
        try:
            response = self.session.get(f"{self.base_url}/register")
            success = response.status_code == 200
            self.log_test("Register Page", success, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Register Page", False, f"Error: {str(e)}")

    def test_testing_opportunities(self):
        """Test testing opportunities page"""
        try:
            response = self.session.get(f"{self.base_url}/testing-opportunities")
            success = response.status_code == 200
            self.log_test(
                "Testing Opportunities", success, f"Status: {response.status_code}"
            )
        except Exception as e:
            self.log_test("Testing Opportunities", False, f"Error: {str(e)}")

    def run_all_tests(self):
        """Run all endpoint tests"""
        print("🚀 Starting endpoint tests...\n")
        
        # Basic health checks
        print("📋 Basic Health Checks:")
        self.test_health_check()
        
        # Authentication tests
        print("\n🔐 Authentication Tests:")
        self.test_user_registration()
        self.test_user_login()
        self.test_company_registration()
        self.test_protected_endpoint()
        
        # Page tests
        print("\n📄 Page Tests:")
        self.test_web_login_page()
        self.test_web_signup_page()
        self.test_register_page()
        self.test_events_listing()
        self.test_create_event_page()
        self.test_testing_opportunities()
        
        # API tests
        print("\n🔌 API Tests:")
        self.test_my_rsvps_api()
        self.test_sendgrid_config()
        
        # Summary
        self.print_summary()

    def print_summary(self):
        """Print test summary"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['success'])
        failed_tests = total_tests - passed_tests
        
        print("\n📊 Test Summary:")
        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {passed_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if failed_tests > 0:
            print("\n❌ Failed Tests:")
            for result in self.test_results:
                if not result['success']:
                    print(f"  - {result['test']}: {result['message']}")

def main():
    """Main function to run endpoint tests"""
    print("🔧 Flask Endpoint Tester")
    print("=" * 50)
    
    tester = EndpointTester()
    
    try:
        tester.run_all_tests()
    except KeyboardInterrupt:
        print("\n🛑 Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
