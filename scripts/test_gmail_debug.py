import requests
import json
import time

def test_gmail_debug():
    """Test Gmail debugging and provide manual testing instructions"""
    
    print("🧪 Gmail Debugging Test")
    print("=" * 50)
    
    api_url = "http://localhost:5000"
    
    # Test API connection
    print("1. Testing API connection...")
    try:
        response = requests.get(f"{api_url}/api/stats", timeout=5)
        if response.ok:
            stats = response.json()
            print(f"   ✅ API working - Total analyzed: {stats['total_analyzed']}")
        else:
            print(f"   ❌ API error: {response.status_code}")
            return
    except Exception as e:
        print(f"   ❌ API connection failed: {e}")
        print("   💡 Make sure backend is running: python app.py")
        return
    
    # Test manual email analysis
    print("\n2. Testing manual Gmail-like email analysis...")
    gmail_test_email = {
        "sender": "notifications@github.com",
        "subject": "Your pull request was merged",
        "content": "Hello! Your pull request #123 has been successfully merged into the main branch. Thank you for your contribution!"
    }
    
    try:
        response = requests.post(f"{api_url}/api/analyze", json=gmail_test_email, timeout=10)
        if response.ok:
            result = response.json()
            print(f"   ✅ Analysis successful: {result['verdict']} ({result['score']}%)")
        else:
            print(f"   ❌ Analysis failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Analysis request failed: {e}")
    
    # Check recent database entries
    print("\n3. Checking recent database entries...")
    try:
        response = requests.get(f"{api_url}/api/debug/recent-analyses")
        if response.ok:
            data = response.json()
            print(f"   📊 Found {data['total_found']} recent entries")
            
            if data['entries']:
                print("   📋 Recent entries:")
                for i, entry in enumerate(data['entries'][:5], 1):
                    print(f"      {i}. {entry['sender_email']} | {entry['subject'][:30]}... | {entry['verdict']}")
            else:
                print("   ⚠️ No entries found in database")
        else:
            print("   ❌ Debug endpoint failed")
    except Exception as e:
        print(f"   ❌ Debug check failed: {e}")
    
    print("\n" + "=" * 50)
    print("🔧 GMAIL DEBUGGING INSTRUCTIONS:")
    print()
    print("1. Open Gmail in Chrome")
    print("2. Open Chrome DevTools (F12)")
    print("3. Go to Console tab")
    print("4. Run these commands to debug:")
    print()
    print("   // Test DOM inspection")
    print("   PhishNetDebug.inspectDOM()")
    print()
    print("   // Test API connection")
    print("   PhishNetDebug.testAPI()")
    print()
    print("   // Force email processing")
    print("   PhishNetDebug.testExtraction()")
    print()
    print("5. Look for detailed debug messages starting with '🛡️ PhishNet DEBUG:'")
    print()
    print("6. Check if you see messages like:")
    print("   - '📧 Gmail: Starting email data extraction...'")
    print("   - '📤 Sending email data to API:'")
    print("   - '✅ Analysis complete for...'")
    print()
    print("7. If extraction fails, check:")
    print("   - Are you viewing an individual email (not inbox list)?")
    print("   - Does the email have visible sender and content?")
    print("   - Are there any JavaScript errors in console?")
    print()
    print("💡 Common Gmail issues:")
    print("- Gmail lazy-loads content - try scrolling or clicking emails")
    print("- Some Gmail views don't show full email content")
    print("- Extension might need to be reloaded after Gmail updates")

if __name__ == "__main__":
    test_gmail_debug()
