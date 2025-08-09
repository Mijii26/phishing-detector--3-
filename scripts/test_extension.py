import time
import webbrowser
from flask import Flask

def test_extension_setup():
    """Test the Chrome extension setup"""
    
    print("🧪 Testing Chrome Extension Setup...")
    print()
    
    # Check 1: Python backend
    print("1. Testing Python Backend...")
    try:
        import requests
        response = requests.get("http://localhost:5000/api/stats", timeout=5)
        if response.status_code == 200:
            print("   ✅ Backend is running and accessible")
        else:
            print("   ❌ Backend returned error:", response.status_code)
            return False
    except requests.exceptions.ConnectionError:
        print("   ❌ Backend is not running!")
        print("   💡 Start it with: python app.py")
        return False
    except Exception as e:
        print(f"   ❌ Backend test failed: {e}")
        return False
    
    # Check 2: Test API endpoint
    print("\n2. Testing API Endpoint...")
    try:
        test_email = {
            "sender": "test@example.com",
            "subject": "Test Email",
            "content": "This is a test email for the phishing detector."
        }
        response = requests.post("http://localhost:5000/api/analyze", 
                               json=test_email, timeout=10)
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ API working - Score: {result.get('score', 'N/A')}")
        else:
            print("   ❌ API test failed:", response.status_code)
            return False
    except Exception as e:
        print(f"   ❌ API test error: {e}")
        return False
    
    # Check 3: Extension files
    print("\n3. Checking Extension Files...")
    import os
    required_files = [
        "extension/manifest.json",
        "extension/content.js", 
        "extension/background.js",
        "extension/popup.html"
    ]
    
    for file_path in required_files:
        if os.path.exists(file_path):
            print(f"   ✅ {file_path}")
        else:
            print(f"   ❌ Missing: {file_path}")
            return False
    
    print("\n🎉 All tests passed!")
    print("\n📋 Next Steps:")
    print("1. Make sure Chrome extension is loaded and enabled")
    print("2. Go to Gmail or Outlook")
    print("3. Open any email")
    print("4. Look for analysis badges on emails")
    print("5. Check browser console (F12) for debug messages")
    
    return True

if __name__ == "__main__":
    test_extension_setup()
