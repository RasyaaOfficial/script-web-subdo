import requests
import sys
import json
from datetime import datetime

class SubdomainResellerAPITester:
    def __init__(self, base_url="https://domain-manager-3.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tokens = {}  # Store tokens for different users
        self.tests_run = 0
        self.tests_passed = 0
        
        # Test users
        self.test_users = {
            'admin': {'email': 'admin@example.com', 'password': 'admin123', 'role': 'admin'},
            'reseller': {'email': 'reseller@example.com', 'password': 'reseller123', 'role': 'reseller'},
            'user1': {'email': 'user1@example.com', 'password': 'user123', 'role': 'user'},
            'user2': {'email': 'user2@example.com', 'password': 'user123', 'role': 'user'}
        }

    def run_test(self, name, method, endpoint, expected_status, data=None, user_type=None, headers=None):
        """Run a single API test"""
        url = f"{self.api_url}/{endpoint}"
        test_headers = {'Content-Type': 'application/json'}
        
        # Add authorization if user_type is specified
        if user_type and user_type in self.tokens:
            test_headers['Authorization'] = f'Bearer {self.tokens[user_type]}'
        
        # Add custom headers
        if headers:
            test_headers.update(headers)

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        print(f"   Method: {method}")
        if data:
            print(f"   Data: {json.dumps(data, indent=2)}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=test_headers)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=test_headers)
            elif method == 'PUT':
                response = requests.put(url, json=data, headers=test_headers)
            elif method == 'DELETE':
                response = requests.delete(url, headers=test_headers)

            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code}")
                try:
                    response_data = response.json()
                    print(f"   Response: {json.dumps(response_data, indent=2)[:200]}...")
                    return True, response_data
                except:
                    return True, {}
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"   Error: {json.dumps(error_data, indent=2)}")
                except:
                    print(f"   Error: {response.text}")
                return False, {}

        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            return False, {}

    def test_login(self, user_type):
        """Test login for a specific user type"""
        user_data = self.test_users[user_type]
        success, response = self.run_test(
            f"Login as {user_type}",
            "POST",
            "auth/login",
            200,
            data=user_data
        )
        
        if success and 'access_token' in response:
            self.tokens[user_type] = response['access_token']
            print(f"   Token stored for {user_type}")
            return True
        return False

    def test_root_endpoint(self):
        """Test root API endpoint"""
        return self.run_test(
            "Root API endpoint",
            "GET",
            "",
            200
        )

    def test_get_tlds(self):
        """Test getting available TLDs"""
        return self.run_test(
            "Get TLDs",
            "GET",
            "settings/tlds",
            200
        )

    def test_create_user(self, creator_type, new_user_data):
        """Test creating a new user"""
        return self.run_test(
            f"Create user as {creator_type}",
            "POST",
            "users",
            200,
            data=new_user_data,
            user_type=creator_type
        )

    def test_list_users(self, user_type):
        """Test listing users (admin only)"""
        expected_status = 200 if user_type == 'admin' else 403
        return self.run_test(
            f"List users as {user_type}",
            "GET",
            "users",
            expected_status,
            user_type=user_type
        )

    def test_create_subdomain(self, user_type, subdomain_data):
        """Test creating a subdomain"""
        return self.run_test(
            f"Create subdomain as {user_type}",
            "POST",
            "subdomains",
            200,
            data=subdomain_data,
            user_type=user_type
        )

    def test_list_subdomains(self, user_type):
        """Test listing subdomains (role-based filtering)"""
        return self.run_test(
            f"List subdomains as {user_type}",
            "GET",
            "subdomains",
            200,
            user_type=user_type
        )

    def test_unauthorized_access(self):
        """Test accessing protected endpoints without token"""
        endpoints = ["users", "subdomains"]
        for endpoint in endpoints:
            success, _ = self.run_test(
                f"Unauthorized access to {endpoint}",
                "GET",
                endpoint,
                401
            )

def main():
    print("🚀 Starting Website Subdomain Reseller API Tests")
    print("=" * 60)
    
    tester = SubdomainResellerAPITester()
    
    # Test 1: Root endpoint
    print("\n📍 TESTING ROOT ENDPOINT")
    tester.test_root_endpoint()
    
    # Test 2: Get TLDs (public endpoint)
    print("\n📍 TESTING PUBLIC ENDPOINTS")
    tester.test_get_tlds()
    
    # Test 3: Test unauthorized access
    print("\n📍 TESTING UNAUTHORIZED ACCESS")
    tester.test_unauthorized_access()
    
    # Test 4: Login all users
    print("\n📍 TESTING AUTHENTICATION")
    login_success = {}
    for user_type in tester.test_users.keys():
        login_success[user_type] = tester.test_login(user_type)
    
    # Check if all logins were successful
    failed_logins = [user for user, success in login_success.items() if not success]
    if failed_logins:
        print(f"\n❌ Login failed for users: {failed_logins}")
        print("Cannot proceed with authenticated tests")
        return 1
    
    # Test 5: User management (role-based)
    print("\n📍 TESTING USER MANAGEMENT")
    
    # Test listing users with different roles
    for user_type in ['admin', 'reseller', 'user1']:
        tester.test_list_users(user_type)
    
    # Test creating users with different permissions
    test_user_data = {
        'email': f'testuser_{datetime.now().strftime("%H%M%S")}@example.com',
        'password': 'testpass123',
        'nama': 'Test User',
        'role': 'user'
    }
    
    # Admin should be able to create users
    tester.test_create_user('admin', test_user_data)
    
    # Reseller should be able to create regular users
    test_user_data['email'] = f'testuser2_{datetime.now().strftime("%H%M%S")}@example.com'
    tester.test_create_user('reseller', test_user_data)
    
    # Regular user should NOT be able to create users
    test_user_data['email'] = f'testuser3_{datetime.now().strftime("%H%M%S")}@example.com'
    success, _ = tester.run_test(
        "Create user as regular user (should fail)",
        "POST",
        "users",
        403,
        data=test_user_data,
        user_type='user1'
    )
    
    # Test 6: Subdomain management
    print("\n📍 TESTING SUBDOMAIN MANAGEMENT")
    
    # First get available TLDs
    success, tlds_response = tester.test_get_tlds()
    if success and tlds_response:
        tld_id = tlds_response[0]['id'] if tlds_response else '1'
        
        # Test subdomain creation with different users
        subdomain_data = {
            'hostname': f'test{datetime.now().strftime("%H%M%S")}',
            'ip_address': '192.168.1.100',
            'tld_id': tld_id
        }
        
        for user_type in ['admin', 'reseller', 'user1']:
            # Use different hostname for each user
            subdomain_data['hostname'] = f'test{user_type}{datetime.now().strftime("%H%M%S")}'
            tester.test_create_subdomain(user_type, subdomain_data)
    
    # Test listing subdomains with different roles
    for user_type in ['admin', 'reseller', 'user1']:
        tester.test_list_subdomains(user_type)
    
    # Test 7: Invalid data handling
    print("\n📍 TESTING ERROR HANDLING")
    
    # Test invalid subdomain data
    invalid_subdomain = {
        'hostname': 'invalid hostname with spaces',
        'ip_address': 'invalid.ip.address',
        'tld_id': '999'
    }
    
    success, _ = tester.run_test(
        "Create subdomain with invalid data",
        "POST",
        "subdomains",
        400,
        data=invalid_subdomain,
        user_type='user1'
    )
    
    # Print final results
    print("\n" + "=" * 60)
    print(f"📊 FINAL RESULTS")
    print(f"Tests passed: {tester.tests_passed}/{tester.tests_run}")
    print(f"Success rate: {(tester.tests_passed/tester.tests_run)*100:.1f}%")
    
    if tester.tests_passed == tester.tests_run:
        print("🎉 All tests passed!")
        return 0
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())