def test_installation():
    """Test if all components are working"""
    
    print("🧪 Testing installation...")
    
    # Test core imports
    try:
        import flask
        print("✅ Flask: OK")
    except ImportError:
        print("❌ Flask: FAILED")
        return False
    
    try:
        import flask_cors
        print("✅ Flask-CORS: OK")
    except ImportError:
        print("❌ Flask-CORS: FAILED")
        return False
    
    try:
        import requests
        print("✅ Requests: OK")
    except ImportError:
        print("❌ Requests: FAILED")
        return False
    
    try:
        import dns.resolver
        print("✅ DNS Python: OK")
    except ImportError:
        print("❌ DNS Python: FAILED")
        return False
    
    try:
        import tldextract
        print("✅ TLD Extract: OK")
    except ImportError:
        print("❌ TLD Extract: FAILED")
        return False
    
    # Test optional imports
    try:
        import textstat
        print("✅ Textstat: OK")
    except ImportError:
        print("⚠️  Textstat: Not available (reading ease analysis disabled)")
    
    try:
        import language_tool_python
        print("✅ Language Tool: OK")
    except ImportError:
        print("⚠️  Language Tool: Not available (grammar checking disabled)")
    
    # Test database creation
    try:
        import sqlite3
        conn = sqlite3.connect(':memory:')
        conn.close()
        print("✅ SQLite: OK")
    except Exception:
        print("❌ SQLite: FAILED")
        return False
    
    # Test app import
    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
        from app import PhishingDetector
        detector = PhishingDetector()
        print("✅ Phishing Detector: OK")
    except Exception as e:
        print(f"❌ Phishing Detector: FAILED - {e}")
        return False
    
    print("\n🎉 Installation test completed successfully!")
    print("You can now run: python app.py")
    return True

if __name__ == "__main__":
    test_installation()
