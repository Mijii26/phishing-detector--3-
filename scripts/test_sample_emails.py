import requests
import json

def test_sample_emails():
    """Test the API with various sample emails"""
    
    API_URL = "http://localhost:5000/api/analyze"
    
    # Test emails with different threat levels
    test_emails = [
        {
            "name": "Safe Email (Vercel Notification)",
            "data": {
                "sender": "notifications@vercel.com",
                "subject": "Your deployment is ready",
                "content": "Hello! Your deployment to production is now live. You can view it at https://your-app.vercel.app. Thanks for using Vercel!"
            },
            "expected_range": (70, 100)
        },
        {
            "name": "Suspicious Email (Urgency)",
            "data": {
                "sender": "support@paypal-security.com",
                "subject": "Action Required: Verify Your Account",
                "content": "Dear customer, we have detected unusual activity on your account. Please verify your identity immediately to avoid suspension. Click here to verify: https://paypal-verify.com"
            },
            "expected_range": (40, 69)
        },
        {
            "name": "Phishing Email (High Risk)",
            "data": {
                "sender": "security@paypaI-verification.tk",
                "subject": "URGENT: Account Suspended - Act Now!",
                "content": "Dear user, your PayPal account has been suspended due to suspicious activity. You must verify your account immediately or it will be permanently closed. Click here now: http://paypal-security-check.tk/verify?urgent=true. Act fast!"
            },
            "expected_range": (0, 49)
        }
    ]
    
    print("🧪 Testing Phishing Detection API with Sample Emails")
    print("=" * 60)
    
    for i, test in enumerate(test_emails, 1):
        print(f"\n{i}. Testing: {test['name']}")
        print(f"   From: {test['data']['sender']}")
        print(f"   Subject: {test['data']['subject'][:50]}...")
        
        try:
            response = requests.post(API_URL, json=test['data'], timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                score = result.get('score', 0)
                verdict = result.get('verdict', 'UNKNOWN')
                
                # Check if score is in expected range
                min_score, max_score = test['expected_range']
                in_range = min_score <= score <= max_score
                
                print(f"   ✅ Score: {score}% | Verdict: {verdict}")
                
                if in_range:
                    print(f"   ✅ Score in expected range ({min_score}-{max_score})")
                else:
                    print(f"   ⚠️  Score outside expected range ({min_score}-{max_score})")
                
                # Show issues if any
                if result.get('details', {}).get('issues'):
                    print(f"   🔍 Issues found: {len(result['details']['issues'])}")
                    for issue in result['details']['issues'][:3]:  # Show first 3
                        print(f"      - {issue}")
                
            else:
                print(f"   ❌ API Error: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            print("   ❌ Connection failed - make sure backend is running")
            break
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    print("\n" + "=" * 60)
    print("💡 Tips:")
    print("- Safe emails should score 70-100%")
    print("- Suspicious emails should score 50-69%") 
    print("- Unsafe emails should score 0-49%")
    print("- Check Gmail for analysis badges on emails")

if __name__ == "__main__":
    test_sample_emails()
