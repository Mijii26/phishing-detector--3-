import subprocess
import sys
import os

def install_dependencies():
    """Install required Python dependencies"""
    
    print("Installing Python dependencies...")
    
    # First install setuptools to fix pkg_resources issue
    try:
        print("Installing setuptools...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--upgrade', 'setuptools>=65.0.0'])
        print("✅ setuptools installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install setuptools: {e}")
        return False
    
    # List of required packages
    packages = [
        'Flask==2.3.3',
        'Flask-CORS==4.0.0',
        'requests==2.31.0',
        'dnspython==2.4.2',
        'textstat==0.7.3',
        'language-tool-python==2.7.1',
        'tldextract==3.6.0'
    ]
    
    for package in packages:
        try:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
            print(f"✅ {package} installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install {package}: {e}")
            return False
    
    print("\n🎉 All dependencies installed successfully!")
    return True

if __name__ == "__main__":
    success = install_dependencies()
    if success:
        print("\nYou can now run the application with: python app.py")
    else:
        print("\nSome dependencies failed to install. Please check the errors above.")
