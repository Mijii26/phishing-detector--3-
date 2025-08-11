import requests
import json

def test_gmail_extraction():
    """Test Gmail-specific email extraction and storage"""
    
    print("🧪 Testing Gmail Email Extraction and Storage")
    print("=" * 50)
    
    # Test emails that simulate Gmail extraction
    test_emails = [
        {
            "name": "Gmail Test 1 - Complete Data",
            "data": {
                "sender": "notifications@github.com",
                "subject": "[GitHub] Your pull request was merged",
                "content": "Hello! Your pull request #123 'Fix login bug' has been successfully merged into the main branch. Thank you for your contribution to the project!"
            }
        },
        {
            "name": "Gmail Test 2 - Missing Subject",
            "data": {
                "sender": "alerts@gmail.com",
                "subject": "",
                "content": "This email has no subject line, which sometimes happens in Gmail extraction."
            }
        },
        {
            "name": "Gmail Test 3 - Suspicious Email",
            "data": {
                "sender": "security@paypaI-alert.tk",
                "subject": "URGENT: Account Suspended - Verify Now!",
                "content": "Your PayPal account has been suspended due to suspicious activity. Click here immediately to verify your account: http://paypal-verify.tk/urgent"
            }
        }
    ]
    
    api_url = "http://localhost:5000"
    
    print("1. Testing API connection...")
    try:
        response = requests.get(f"{api_url}/api/stats", timeout=5)
        if response.ok:
            print("   ✅ API is running")
        else:
            print(f"   ❌ API returned error: {response.status_code}")
            return
    except Exception as e:
        print(f"   ❌ API connection failed: {e}")
        print("   💡 Make sure to run: python app.py")
        return
    
    print("\n2. Getting initial database stats...")
    try:
        response = requests.get(f"{api_url}/api/stats")
        initial_stats = response.json()
        print(f"   📊 Initial total: {initial_stats['total_analyzed']}")
    except Exception as e:
        print(f"   ❌ Failed to get initial stats: {e}")
        initial_stats = {'total_analyzed': 0}
    
    print("\n3. Testing email analysis and storage...")
    stored_count = 0
    
    for i, test in enumerate(test_emails, 1):
        print(f"\n   Test {i}: {test['name']}")
        print(f"   📧 From: {test['data']['sender']}")
        print(f"   📝 Subject: {test['data']['subject'] or '(empty)'}")
        
        try:
            # Analyze email
            response = requests.post(f"{api_url}/api/analyze", 
                                   json=test['data'], timeout=10)
            
            if response.ok:
                result = response.json()
                print(f"   ✅ Analysis: {result['verdict']} ({result['score']}%)")
                stored_count += 1
            else:
                print(f"   ❌ Analysis failed: {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ Request failed: {e}")
    
    print(f"\n4. Checking if emails were stored...")
    try:
        # Wait a moment for storage to complete
        import time
        time.sleep(2)
        
        response = requests.get(f"{api_url}/api/stats")
        final_stats = response.json()
        
        expected_total = initial_stats['total_analyzed'] + stored_count
        actual_total = final_stats['total_analyzed']
        
        print(f"   📊 Expected total: {expected_total}")
        print(f"   📊 Actual total: {actual_total}")
        
        if actual_total >= expected_total:
            print("   ✅ All emails appear to be stored correctly!")
        else:
            print("   ❌ Some emails may not have been stored")
            print("   💡 Check debug endpoint: /api/debug/recent-analyses")
            
    except Exception as e:
        print(f"   ❌ Failed to verify storage: {e}")
    
    print("\n5. Checking recent database entries...")
    try:
        response = requests.get(f"{api_url}/api/debug/recent-analyses")
        if response.ok:
            debug_data = response.json()
            print(f"   📋 Found {debug_data['total_found']} recent entries")
            
            for entry in debug_data['entries'][:5]:
                print(f"      - {entry['sender_email']} | {entry['subject'][:30]}... | {entry['verdict']}")
        else:
            print("   ❌ Debug endpoint not available")
    except Exception as e:
        print(f"   ❌ Debug check failed: {e}")
    
    print("\n" + "=" * 50)
    print("💡 Next steps:")
    print("- Run: python scripts/inspect_database.py")
    print("- Enable debug mode: PHISHNET_DEBUG=1")
    print("- Check Chrome extension console for errors")

if __name__ == "__main__":
    test_gmail_extraction()
