import requests
import json

def test_backend():
    """Test the backend API thoroughly"""
    
    print("🧪 Testing Phishing Email Detector Backend")
    print("=" * 50)
    
    base_url = "http://localhost:5000"
    
    # Test 1: Check if server is running
    print("\n1. Testing server connection...")
    try:
        response = requests.get(f"{base_url}/api/stats", timeout=5)
        if response.status_code == 200:
            print("✅ Server is running and accessible")
            stats = response.json()
            print(f"   📊 Stats: {stats}")
        else:
            print(f"❌ Server returned error: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Server is not running!")
        print("💡 Start it with: python app.py")
        return False
    except Exception as e:
        print(f"❌ Connection test failed: {e}")
        return False
    
    # Test 2: Test email analysis
    print("\n2. Testing email analysis...")
    test_emails = [
        {
            "name": "Safe Email",
            "data": {
                "sender": "notifications@github.com",
                "subject": "Your pull request was merged",
                "content": "Hello! Your pull request #123 has been successfully merged into the main branch. Thank you for your contribution!"
            }
        },
        {
            "name": "Phishing Email",
            "data": {
                "sender": "security@paypaI-alert.tk",
                "subject": "URGENT: Account Suspended - Verify Now!",
                "content": "Your account has been suspended due to suspicious activity. Click here immediately to verify: http://paypal-verify.tk/urgent"
            }
        }
    ]
    
    for test in test_emails:
        print(f"\n   Testing: {test['name']}")
        try:
            response = requests.post(f"{base_url}/api/analyze", 
                                   json=test['data'], timeout=10)
            if response.status_code == 200:
                result = response.json()
                print(f"   ✅ Score: {result.get('score', 'N/A')}% | Verdict: {result.get('verdict', 'N/A')}")
                if result.get('details', {}).get('issues'):
                    print(f"   🔍 Issues: {len(result['details']['issues'])}")
            else:
                print(f"   ❌ Analysis failed: {response.status_code}")
        except Exception as e:
            print(f"   ❌ Analysis error: {e}")
    
    # Test 3: Test whitelist
    print("\n3. Testing whitelist API...")
    try:
        response = requests.get(f"{base_url}/api/whitelist", timeout=5)
        if response.status_code == 200:
            whitelist = response.json()
            print(f"   ✅ Whitelist loaded: {len(whitelist)} entries")
        else:
            print(f"   ❌ Whitelist test failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Whitelist error: {e}")
    
    # Test 4: Test history
    print("\n4. Testing history API...")
    try:
        response = requests.get(f"{base_url}/api/history", timeout=5)
        if response.status_code == 200:
            history = response.json()
            print(f"   ✅ History loaded: {history.get('total', 0)} entries")
        else:
            print(f"   ❌ History test failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ History error: {e}")
    
    print("\n" + "=" * 50)
    print("🎉 Backend testing completed!")
    print("💡 If all tests passed, the Chrome extension should work")
    
    return True

if __name__ == "__main__":
    test_backend()
