# 🛡️ PhishNet

A comprehensive phishing email detection system with Chrome extension, web interface, and API. This system provides real-time email analysis to protect users from phishing attacks.

## ✨ Features

### 🔍 Advanced Analysis Engine
- **Domain Reputation Checking**: Validates sender domains and checks for suspicious patterns
- **Content Pattern Analysis**: Detects common phishing phrases and urgency tactics
- **URL Security Analysis**: Examines embedded links for malicious characteristics
- **Grammar & Spelling Detection**: Identifies poor language quality often found in phishing emails
- **Real-time Scoring**: Provides 0-100 security scores with instant verdicts

### 🛡️ Complete Whitelist System
- **Trusted Entities**: Whitelist senders, domains, and keywords
- **Smart Management**: Easy add/remove functionality with notes
- **Import/Export**: Backup and restore whitelist configurations
- **One-click Whitelist**: Add trusted items directly from analysis results

### 📊 Professional Web Interface
- **Dashboard**: Real-time statistics and security overview
- **Interactive Analyzer**: Test emails manually with detailed results
- **Analysis History**: View past scans with pagination and filtering
- **Dark/Light Mode**: Toggle between themes with persistent settings
- **Responsive Design**: Works on desktop, tablet, and mobile devices

### 🔌 Chrome Extension
- **Real-time Monitoring**: Automatically scans incoming emails
- **Instant Notifications**: Color-coded alerts (Green: Safe, Yellow: Suspicious, Red: Unsafe)
- **Gmail & Outlook Support**: Works with major email providers
- **Detailed Analysis**: Click for comprehensive security reports

### 🚀 RESTful API
- **Programmatic Access**: Integrate with other applications
- **JSON Responses**: Standard API format for easy integration
- **Comprehensive Endpoints**: Analyze, whitelist, history, and statistics

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Chrome browser (for extension)
- Internet connection (for domain reputation checks)

### Installation

1. **Clone or download the project files**

2. **Install Python dependencies**:
   \`\`\`bash
   python scripts/install_dependencies.py
   \`\`\`

3. **Set up the database**:
   \`\`\`bash
   python scripts/setup_database.py
   \`\`\`

4. **Start the application**:
   \`\`\`bash
   python app.py
   \`\`\`

5. **Access the web interface**:
   Open http://localhost:5000 in your browser

### Chrome Extension Setup

1. **Open Chrome Extensions**:
   - Go to `chrome://extensions/`
   - Enable "Developer mode" (top right toggle)

2. **Load the extension**:
   - Click "Load unpacked"
   - Select the `extension` folder from this project
   - The extension icon should appear in your toolbar

3. **Configure permissions**:
   - The extension will request permissions for Gmail and Outlook
   - Click "Allow" to enable real-time email scanning

## 📖 Usage Guide

### Web Interface

#### Dashboard
- View overall security statistics
- Monitor email analysis trends
- Toggle between dark and light themes
- Access quick actions and settings

#### Email Analyzer
- Paste email content for manual analysis
- Get detailed security reports
- Test suspicious emails safely

#### Whitelist Management
- Add trusted senders, domains, or keywords
- Import/export whitelist configurations
- Manage existing whitelist entries

#### Analysis History
- Review past email scans
- Filter by date, sender, or verdict
- Export analysis reports

### Chrome Extension

#### Automatic Scanning
- Extension automatically detects new emails
- Analysis happens in the background
- Results appear as colored badges on emails

#### Notification System
- **Green (70-100%)**: ✅ Safe - Email appears legitimate
- **Yellow (50-69%)**: ⚠️ Suspicious - Exercise caution
- **Red (0-49%)**: 🚨 Unsafe - Likely phishing attempt

#### Detailed Analysis
- Click on any analysis badge for detailed results
- View specific security issues found
- See domain, content, and URL scores

### API Usage

#### Analyze Email
\`\`\`bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "sender": "suspicious@example.com",
    "subject": "Urgent: Verify your account now!",
    "content": "Click here to verify your account immediately..."
  }'
\`\`\`

#### Get Statistics
\`\`\`bash
curl http://localhost:5000/api/stats
\`\`\`

#### Manage Whitelist
\`\`\`bash
# Add whitelist item
curl -X POST http://localhost:5000/api/whitelist \
  -H "Content-Type: application/json" \
  -d '{
    "type": "domain",
    "value": "trusted-company.com",
    "notes": "Corporate partner"
  }'

# Get whitelist
curl http://localhost:5000/api/whitelist
\`\`\`

## 🔧 Configuration

### Security Thresholds
The system uses the following scoring thresholds:
- **70-100**: Safe (Green notification)
- **50-69**: Suspicious (Yellow notification)
- **0-49**: Unsafe (Red notification)

### Analysis Components
- **Domain Score (30% weight)**: Domain reputation and legitimacy
- **Content Score (50% weight)**: Text analysis and phishing patterns
- **URL Score (20% weight)**: Link safety and characteristics

### Customization
You can modify the analysis parameters in `app.py`:
- Phishing patterns (line 25)
- Suspicious TLDs (line 43)
- Scoring weights (line 180)
- Notification thresholds (line 185)

## 🛠️ Technical Architecture

### Backend (Python/Flask)
- **Flask**: Web framework and API server
- **SQLite**: Database for analysis history and whitelist
- **DNS Resolution**: Domain reputation checking
- **Language Processing**: Grammar and readability analysis
- **Pattern Matching**: Phishing detection algorithms

### Frontend (HTML/CSS/JavaScript)
- **Responsive Design**: Works on all device sizes
- **Chart.js**: Interactive statistics visualization
- **Tailwind CSS**: Modern styling framework with dark mode
- **Real-time Updates**: Dynamic content loading

### Chrome Extension
- **Manifest V3**: Latest Chrome extension standard
- **Content Scripts**: Email detection and analysis
- **Background Service**: API communication and notifications
- **Storage API**: Local data persistence

### Database Schema
- **email_analysis**: Stores analysis results and history
- **whitelist**: Manages trusted entities
- **domain_reputation**: Caches domain reputation data

## 🔒 Security & Privacy

### Data Protection
- All analysis is performed locally or on your server
- No email content is sent to third-party services
- Database is stored locally and encrypted
- Whitelist data remains private

### Network Security
- HTTPS support for production deployment
- CORS protection for API endpoints
- Input validation and sanitization
- SQL injection prevention

### Privacy Features
- No tracking or analytics
- No data collection or sharing
- Local processing only
- User-controlled data retention

## 🚀 Deployment

### Production Setup

1. **Environment Configuration**:
   \`\`\`bash
   export FLASK_ENV=production
   export FLASK_DEBUG=False
   \`\`\`

2. **Database Security**:
   - Use PostgreSQL or MySQL for production
   - Enable database encryption
   - Set up regular backups

3. **Web Server**:
   - Use Gunicorn or uWSGI
   - Configure Nginx reverse proxy
   - Enable HTTPS with SSL certificates

4. **Chrome Extension**:
   - Package extension for Chrome Web Store
   - Update API endpoints to production URLs
   - Submit for review and publication

### Docker Deployment
\`\`\`dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "app.py"]
\`\`\`

## Environment variables (.env)

Create a `.env` file in the project root (same directory as `app.py`) and add the keys you want to enable:

```
cp .env.example .env
# edit .env
```

Supported variables:
- `VT_API_KEY` or `VIRUSTOTAL_API_KEY`: VirusTotal API key
- `ABUSEIPDB_KEY` or `ABUSEIPDB_API_KEY`: AbuseIPDB key
- `WHOISXML_KEY` or `WHOISXMLAPI_KEY`: WhoisXML key
- `URLSCAN_API_KEY` or `URLSCAN_KEY`: urlscan.io key
- `GOOGLE_SAFE_BROWSING_KEY`: Google Safe Browsing key
- `URLHAUS_ENABLED`: set to `1` or `true` to enable URLHaus lookups

The backend automatically loads `.env` via `python-dotenv`.

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes** and test thoroughly
4. **Commit your changes**: `git commit -m 'Add amazing feature'`
5. **Push to the branch**: `git push origin feature/amazing-feature`
6. **Open a Pull Request**

### Development Setup
1. Install development dependencies
2. Run tests: `python -m pytest`
3. Check code style: `flake8 .`
4. Test extension in Chrome developer mode

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

### Common Issues

**Extension not working?**
- Check Chrome permissions
- Verify API server is running
- Check browser console for errors

**Analysis seems inaccurate?**
- Update phishing patterns
- Adjust scoring weights
- Add items to whitelist

**Performance issues?**
- Limit analysis history
- Optimize database queries
- Reduce analysis frequency

### Getting Help
- Check the documentation
- Review common issues above
- Open an issue on GitHub
- Contact support team

## 🎯 Roadmap

### Upcoming Features
- [ ] Machine learning integration
- [ ] Advanced threat intelligence
- [ ] Mobile app support
- [ ] Enterprise features
- [ ] Multi-language support
- [ ] Advanced reporting
- [ ] Integration with security tools

### Version History
- **v1.0.0**: Initial release with core features
- **v1.1.0**: Chrome extension improvements
- **v1.2.0**: Enhanced analysis algorithms
- **v1.3.0**: Dark mode and UI improvements
- **v2.0.0**: Machine learning integration (planned)

---

**⚠️ Disclaimer**: This tool is designed to assist in identifying potential phishing emails but should not be the only security measure. Always exercise caution with suspicious emails and verify important communications through alternative channels.

**🛡️ Stay Safe**: Keep the system updated, maintain your whitelist, and report false positives to improve accuracy.
