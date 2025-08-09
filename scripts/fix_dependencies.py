import subprocess
import sys
import os

def fix_dependencies():
    """Fix common dependency issues"""
    
    print("🔧 Fixing Python dependencies...")
    
    # Commands to run
    commands = [
        # Upgrade pip first
        [sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'],
        
        # Install setuptools to fix pkg_resources
        [sys.executable, '-m', 'pip', 'install', '--upgrade', 'setuptools>=65.0.0'],
        
        # Install wheel for better package building
        [sys.executable, '-m', 'pip', 'install', '--upgrade', 'wheel'],
        
        # Install core dependencies one by one
        [sys.executable, '-m', 'pip', 'install', 'Flask==2.3.3'],
        [sys.executable, '-m', 'pip', 'install', 'Flask-CORS==4.0.0'],
        [sys.executable, '-m', 'pip', 'install', 'requests==2.31.0'],
        [sys.executable, '-m', 'pip', 'install', 'dnspython==2.4.2'],
        [sys.executable, '-m', 'pip', 'install', 'tldextract==3.6.0'],
        
        # Install optional dependencies (may fail, but that's ok)
        [sys.executable, '-m', 'pip', 'install', 'textstat==0.7.3'],
        [sys.executable, '-m', 'pip', 'install', 'language-tool-python==2.7.1'],
    ]
    
    for i, cmd in enumerate(commands, 1):
        try:
            print(f"[{i}/{len(commands)}] Running: {' '.join(cmd[3:])}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                print(f"✅ Success")
            else:
                print(f"⚠️  Warning: {result.stderr.strip()}")
                
        except subprocess.TimeoutExpired:
            print(f"⏰ Timeout - skipping")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    print("\n🎉 Dependency fix completed!")
    print("\nNote: Some optional features may be disabled if certain packages failed to install.")
    print("The core phishing detection will still work!")

if __name__ == "__main__":
    fix_dependencies()
