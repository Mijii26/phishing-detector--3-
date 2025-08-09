from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
import sqlite3
import json
import re
import urllib.parse
from urllib.parse import urlparse  # Add this import
import requests
import dns.resolver
import socket
import time
import idna
from datetime import datetime, timedelta

import hashlib
import os

# Handle textstat import with fallback
try:
    from textstat import flesch_reading_ease
    TEXTSTAT_AVAILABLE = True
except ImportError:
    print("Warning: textstat not available. Reading ease analysis will be skipped.")
    TEXTSTAT_AVAILABLE = False
    def flesch_reading_ease(text):
        return 50  # Default neutral score

# Handle language_tool_python import with fallback
try:
    import language_tool_python
    LANGUAGE_TOOL_AVAILABLE = True
except ImportError:
    print("Warning: language_tool_python not available. Grammar checking will be skipped.")
    LANGUAGE_TOOL_AVAILABLE = False
    class MockLanguageTool:
        def check(self, text):
            return []
        def close(self):
            pass
    
    # Create a mock module
    class MockLanguageToolModule:
        def LanguageTool(self, lang):
            return MockLanguageTool()
    
    language_tool_python = MockLanguageToolModule()

import tldextract

try:
    import whois  # pip install python-whois
    WHOIS_AVAILABLE = True
except Exception:
    WHOIS_AVAILABLE = False

app = Flask(__name__)
CORS(app)

class PhishingDetector:
    def __init__(self):
        self.db_path = 'data/phishing_detector.db'
        
        # Initialize grammar tool if available
        if LANGUAGE_TOOL_AVAILABLE:
            try:
                self.grammar_tool = language_tool_python.LanguageTool('en-US')
                print("✅ Grammar tool initialized successfully")
            except Exception as e:
                print(f"Warning: Could not initialize grammar tool: {e}")
                self.grammar_tool = None
        else:
            self.grammar_tool = None
            print("⚠️ Grammar tool not available - using fallback")
        
        # Phishing patterns
        self.phishing_patterns = [
            r'urgent.{0,20}action.{0,20}required',
            r'verify.{0,20}account',
            r'suspended.{0,20}account',
            r'click.{0,20}here.{0,20}immediately',
            r'limited.{0,20}time.{0,20}offer',
            r'congratulations.{0,20}winner',
            r'claim.{0,20}prize',
            r'tax.{0,20}refund',
            r'security.{0,20}alert',
            r'unusual.{0,20}activity',
            r'confirm.{0,20}identity',
            r'update.{0,20}payment',
            r'expire.{0,20}today',
            r'act.{0,20}now',
            r'dear.{0,20}customer',
            r'dear.{0,20}user',
            r'password.{0,20}reset',
            r'login.{0,20}now',
            r'update.{0,20}credentials',
            r'bank.{0,20}account',
            r'confirm.{0,20}payment',
            r'gift.{0,20}card',
            r'crypto.{0,20}investment',
            r'wire.{0,20}transfer',
            r'2fa.{0,10}disable',
        ]
        
        # Suspicious TLDs
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click', '.download']
        
        self.known_brands = {
            'paypal.com', 'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'vercel.com', 'netflix.com', 'bankofamerica.com', 'chase.com',
            'wellsfargo.com', 'citibank.com', 'github.com'
        }
        self.shorteners = {'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','cutt.ly','rebrand.ly'}
        self.domain_cache_ttl = 24 * 3600  # seconds
        
    def __del__(self):
        # Clean up grammar tool
        if hasattr(self, 'grammar_tool') and self.grammar_tool and LANGUAGE_TOOL_AVAILABLE:
            try:
                self.grammar_tool.close()
            except:
                pass
        
    def get_db_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def extract_urls(self, text):
        """Extract URLs from email content"""
        # Find URLs in plain text
        urls = re.findall(r'(https?://[^\s<>"\'\)]+)', text)
        # Also try to capture HTML anchor hrefs if any HTML slipped in
        hrefs = re.findall(r'href=["\'](https?://[^"\']+)["\']', text, flags=re.IGNORECASE)
        all_urls = list(set(urls + hrefs))
        return all_urls
    
    def _is_ip(self, host: str) -> bool:
        if not host:
            return False
        # IPv4
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host):
            return True
        # IPv6 (basic)
        return ':' in host

    def _lev_ratio(self, a: str, b: str) -> float:
        # Simple Levenshtein ratio without external deps
        a, b = a.lower(), b.lower()
        m, n = len(a), len(b)
        if m == 0 or n == 0:
            return 0.0
        dp = [[0]*(n+1) for _ in range(m+1)]
        for i in range(m+1): dp[i][0] = i
        for j in range(n+1): dp[0][j] = j
        for i in range(1, m+1):
            for j in range(1, n+1):
                cost = 0 if a[i-1] == b[j-1] else 1
                dp[i][j] = min(
                    dp[i-1][j] + 1,
                    dp[i][j-1] + 1,
                    dp[i-1][j-1] + cost
                )
        dist = dp[m][n]
        return 1.0 - dist / max(m, n)

    def _domain_age_days(self, domain: str) -> int | None:
        if not WHOIS_AVAILABLE or not domain:
            return None
        try:
            w = whois.whois(domain)
            created = w.creation_date
            if isinstance(created, list):
                created = min([d for d in created if isinstance(d, datetime)], default=None)
            if not isinstance(created, datetime):
                return None
            return (datetime.utcnow() - created.replace(tzinfo=None)).days
        except Exception:
            return None

    def _has_spf(self, domain: str) -> bool:
        try:
            txts = dns.resolver.resolve(domain, 'TXT', raise_on_no_answer=False)
            for r in txts:
                v = ''.join([b.decode('utf-8') if isinstance(b, (bytes, bytearray)) else str(b) for b in r.strings]) if hasattr(r, 'strings') else str(r)
                if 'v=spf1' in v.lower():
                    return True
        except Exception:
            pass
        return False

    def _dmarc_policy(self, domain: str) -> str | None:
        try:
            dmarc_domain = f"_dmarc.{domain}"
            txts = dns.resolver.resolve(dmarc_domain, 'TXT', raise_on_no_answer=False)
            for r in txts:
                v = ''.join([b.decode('utf-8') if isinstance(b, (bytes, bytearray)) else str(b) for b in r.strings]) if hasattr(r, 'strings') else str(r)
                if 'v=dmarc1' in v.lower():
                    m = re.search(r'\bp=([a-zA-Z]+)', v, re.IGNORECASE)
                    return m.group(1).lower() if m else 'none'
        except Exception:
            return None
        return None

    def _mx_exists(self, domain: str) -> bool:
        try:
            answers = dns.resolver.resolve(domain, 'MX', raise_on_no_answer=False)
            return answers is not None and len(answers) > 0
        except Exception:
            return False

    def _looks_punycode(self, domain: str) -> bool:
        return 'xn--' in domain

    def _similar_to_brand(self, domain: str) -> bool:
        try:
            ext = tldextract.extract(domain)
            sld = ext.domain  # second-level label only
            for brand in self.known_brands:
                brand_sld = tldextract.extract(brand).domain
                if sld == brand_sld:
                    # exact match of SLD is okay only if suffix matches brand's suffix. Otherwise could be typosquat on different TLD.
                    if f".{ext.suffix}" != f".{tldextract.extract(brand).suffix}":
                        return True
                ratio = self._lev_ratio(sld, brand_sld)
                if ratio >= 0.85 and sld != brand_sld:
                    return True
        except Exception:
            pass
        return False

    def _check_external_reputation(self, url: str, domain: str) -> tuple[int, list[str]]:
        # Optional integrations you can enable by setting env vars:
        # - GOOGLE_SAFE_BROWSING_KEY
        # - URLSCAN_API_KEY
        score_adj = 0
        issues = []
        gsb_key = os.getenv('GOOGLE_SAFE_BROWSING_KEY')
        if gsb_key:
            try:
                payload = {
                    "client": {"clientId": "phishnet", "clientVersion": "1.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}]
                    }
                }
                resp = requests.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_key}",
                    json=payload, timeout=8
                )
                if resp.ok and resp.json().get("matches"):
                    score_adj -= 50
                    issues.append("Flagged by Google Safe Browsing")
            except Exception:
                pass
        # You can extend with urlscan.io quick reputation, PhishTank, etc.
        return score_adj, issues
    
    def check_domain_reputation(self, domain: str) -> tuple[int, list[str]]:
        score = 100
        issues: list[str] = []
        if not domain:
            return 40, ["No domain provided"]

        # Resolve A record
        try:
            socket.gethostbyname(domain)
            resolves = True
        except Exception:
            resolves = False

        if not resolves:
            score -= 50
            issues.append("Domain does not resolve")
            return max(0, score), issues

        # MX presence (mail-ready domains tend to have MX)
        if not self._mx_exists(domain):
            score -= 15
            issues.append("No MX record found")

        # SPF
        if not self._has_spf(domain):
            score -= 10
            issues.append("No SPF record")

        # DMARC
        policy = self._dmarc_policy(domain)
        if policy is None:
            score -= 10
            issues.append("No DMARC record")
        elif policy == 'none':
            score -= 5
            issues.append("DMARC policy is none")

        # Suspicious attributes
        ext = tldextract.extract(domain)
        suffix = f".{ext.suffix}" if ext.suffix else ""
        if suffix in self.suspicious_tlds:
            score -= 25
            issues.append("Suspicious top-level domain")

        if self._is_ip(domain):
            score -= 30
            issues.append("URL uses IP address instead of domain")

        if self._looks_punycode(domain):
            score -= 25
            issues.append("Punycode domain detected")

        if len(domain) > 35:
            score -= 10
            issues.append("Very long domain name")
        elif len(domain) > 25:
            score -= 5
            issues.append("Long domain name")

        # Typosquatting vs known brands
        if self._similar_to_brand(domain):
            score -= 25
            issues.append("Possible typosquatting against known brand")

        # Domain age (if available)
        age_days = self._domain_age_days(domain)
        if age_days is not None:
            if age_days < 90:
                score -= 20
                issues.append("Newly registered domain (<90 days)")
            elif age_days < 365:
                score -= 10
                issues.append("Young domain (<1 year)")

        return max(0, score), issues
    
    def analyze_content(self, content):
        """Analyze email content for phishing patterns"""
        score = 100
        issues = []
        
        if not content:
            return 50, ["No content to analyze"]
        
        # Check for phishing patterns
        pattern_matches = 0
        for pattern in self.phishing_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                pattern_matches += 1
        
        if pattern_matches > 0:
            score -= min(pattern_matches * 15, 60)
            issues.append(f"Found {pattern_matches} phishing pattern(s)")
        
        # Grammar and spelling check (if available)
        if self.grammar_tool and LANGUAGE_TOOL_AVAILABLE:
            try:
                matches = self.grammar_tool.check(content[:1000])  # Limit to first 1000 chars
                if len(matches) > 5:
                    score -= min(len(matches) * 2, 20)
                    issues.append(f"Poor grammar/spelling ({len(matches)} errors)")
            except Exception as e:
                print(f"Grammar check failed: {e}")
    
        # Reading level check (if available)
        if TEXTSTAT_AVAILABLE:
            try:
                reading_ease = flesch_reading_ease(content)
                if reading_ease < 30:  # Very difficult to read
                    score -= 10
                    issues.append("Unusually complex language")
            except Exception as e:
                print(f"Reading ease check failed: {e}")
    
        # Check for excessive urgency words
        urgency_words = ['urgent', 'immediate', 'asap', 'hurry', 'quick', 'fast', 'now', 'today']
        urgency_count = sum(1 for word in urgency_words if word in content.lower())
        if urgency_count > 3:
            score -= 15
            issues.append("Excessive urgency language")
        
        # Excessive links in content (heuristic on plain text)
        link_count = len(re.findall(r'http[s]?://', content, re.IGNORECASE))
        if link_count >= 3:
            score -= 10
            issues.append("Multiple links present")
        
        return max(0, score), issues
    
    def analyze_urls(self, urls: list[str]) -> tuple[int, list[str]]:
        if not urls:
            return 100, []

        overall_issues: list[str] = []
        per_url_scores: list[int] = []

        for url in urls:
            url_score = 100
            try:
                parsed = urlparse(url)
                scheme = (parsed.scheme or '').lower()
                domain = (parsed.netloc or '').lower()

                # Reputation of URL domain
                d_score, d_issues = self.check_domain_reputation(domain)
                overall_issues.extend([f"{domain}: {i}" for i in d_issues])
                if d_score < 80:
                    url_score -= min(30, 100 - d_score)

                # HTTPS required
                if scheme != 'https':
                    url_score -= 10
                    overall_issues.append("Non-HTTPS link")

                # Suspicious URL constructs
                full = url.lower()
                if '@' in full:
                    url_score -= 15
                    overall_issues.append("URL contains @ (obfuscation)")

                if self._is_ip(domain):
                    url_score -= 15
                    overall_issues.append("IP-based link")

                # Shorteners penalized more
                if any(s in domain for s in self.shorteners):
                    url_score -= 20
                    overall_issues.append("URL shortener detected")

                # Long / deep path
                if len(full) > 120:
                    url_score -= 5
                    overall_issues.append("Unusually long URL")
                if parsed.path.count('/') > 6:
                    url_score -= 5
                    overall_issues.append("Deep URL path structure")

                # Suspicious query params
                suspicious_params = ['login', 'verify', 'password', 'account', 'update', 'reset', 'pin']
                if any(p in (parsed.query or '').lower() for p in suspicious_params):
                    url_score -= 10
                    overall_issues.append("Suspicious query parameters")

                # Optional external reputation (if enabled)
                adj, rep_issues = self._check_external_reputation(url, domain)
                if adj != 0:
                    url_score += adj
                    overall_issues.extend(rep_issues)

            except Exception:
                url_score -= 20
                overall_issues.append(f"Malformed URL: {url}")

            per_url_scores.append(max(0, url_score))

        # Be strict: take the minimum score across all URLs in the email
        final_url_score = max(0, min(per_url_scores))
        return final_url_score, overall_issues
    
    def check_whitelist(self, sender_email, sender_domain, content):
        """Check if email components are whitelisted"""
        try:
            conn = self.get_db_connection()
            
            # Check sender email
            result = conn.execute(
                "SELECT * FROM whitelist WHERE type = 'email' AND value = ?",
                (sender_email,)
            ).fetchone()
            if result:
                conn.close()
                return True, "Sender email is whitelisted"
            
            # Check sender domain
            result = conn.execute(
                "SELECT * FROM whitelist WHERE type = 'domain' AND value = ?",
                (sender_domain,)
            ).fetchone()
            if result:
                conn.close()
                return True, "Sender domain is whitelisted"
            
            # Check keywords
            keywords = conn.execute(
                "SELECT value FROM whitelist WHERE type = 'keyword'"
            ).fetchall()
            
            for keyword_row in keywords:
                if keyword_row['value'].lower() in content.lower():
                    conn.close()
                    return True, f"Whitelisted keyword found: {keyword_row['value']}"
            
            conn.close()
            return False, ""
        except Exception as e:
            print(f"Whitelist check failed: {e}")
            return False, ""
    
    def analyze_email(self, email_data):
        """Main email analysis function"""
        try:
            sender_email = email_data.get('sender', '')
            subject = email_data.get('subject', '')
            content = email_data.get('content', '')
            
            print(f"🔍 Analyzing email from: {sender_email}")
            
            # Extract domain from sender
            sender_domain = sender_email.split('@')[-1] if '@' in sender_email else ''
            
            # Check whitelist first
            is_whitelisted, whitelist_reason = self.check_whitelist(sender_email, sender_domain, content)
            if is_whitelisted:
                print(f"✅ Email whitelisted: {whitelist_reason}")
                return {
                    'score': 100,
                    'verdict': 'SAFE',
                    'reason': whitelist_reason,
                    'details': {'whitelisted': True}
                }
            
            # Extract URLs
            urls = self.extract_urls(content)
            
            # Perform analysis
            domain_score, domain_issues = self.check_domain_reputation(sender_domain) if sender_domain else (40, ["No sender domain"])
            content_score, content_issues = self.analyze_content(content + ' ' + subject)
            url_score, url_issues = self.analyze_urls(urls)
            
            # Calculate weighted final score
            final_score = int((domain_score * 0.35 + content_score * 0.4 + url_score * 0.25))
            
            # Determine verdict
            if final_score >= 70:
                verdict = 'SAFE'
            elif final_score >= 50:
                verdict = 'SUSPICIOUS'
            else:
                verdict = 'UNSAFE'
            
            # Compile analysis details
            all_issues = domain_issues + content_issues + url_issues
            
            analysis_result = {
                'score': final_score,
                'verdict': verdict,
                'details': {
                    'domain_score': domain_score,
                    'content_score': content_score,
                    'url_score': url_score,
                    'issues': all_issues,
                    'urls_found': urls,
                    'sender_domain': sender_domain
                }
            }
            
            print(f"📊 Analysis complete: {verdict} ({final_score}%)")
            
            # Store in database
            self.store_analysis(email_data, analysis_result)
            
            return analysis_result
            
        except Exception as e:
            print(f"❌ Analysis error: {e}")
            return {
                'score': 50,
                'verdict': 'ERROR',
                'details': {'error': str(e)}
            }
    
    def store_analysis(self, email_data, analysis_result):
        """Store analysis results in database"""
        try:
            conn = self.get_db_connection()
            
            email_id = hashlib.md5(
                (email_data.get('sender', '') + email_data.get('subject', '') + 
                 str(datetime.now())).encode()
            ).hexdigest()
            
            conn.execute('''
                INSERT OR REPLACE INTO email_analysis 
                (email_id, sender_email, sender_domain, subject, content_preview, 
                 urls, score, verdict, analysis_details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                email_id,
                email_data.get('sender', ''),
                analysis_result['details'].get('sender_domain', ''),
                email_data.get('subject', ''),
                email_data.get('content', '')[:200],
                json.dumps(analysis_result['details'].get('urls_found', [])),
                analysis_result['score'],
                analysis_result['verdict'],
                json.dumps(analysis_result['details'])
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Failed to store analysis: {e}")

# Initialize detector
detector = PhishingDetector()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_email():
    """API endpoint to analyze email"""
    try:
        email_data = request.json
        if not email_data:
            return jsonify({'error': 'No email data provided'}), 400
        
        result = detector.analyze_email(email_data)
        return jsonify(result)
    
    except Exception as e:
        print(f"API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/whitelist', methods=['GET', 'POST', 'DELETE'])
def manage_whitelist():
    """Manage whitelist entries"""
    try:
        conn = detector.get_db_connection()
        
        if request.method == 'GET':
            entries = conn.execute(
                "SELECT * FROM whitelist ORDER BY type, value"
            ).fetchall()
            conn.close()
            return jsonify([dict(entry) for entry in entries])
        
        elif request.method == 'POST':
            data = request.json
            try:
                conn.execute(
                    "INSERT INTO whitelist (type, value, notes) VALUES (?, ?, ?)",
                    (data['type'], data['value'], data.get('notes', ''))
                )
                conn.commit()
                conn.close()
                return jsonify({'success': True})
            except sqlite3.IntegrityError:
                conn.close()
                return jsonify({'error': 'Entry already exists'}), 400
        
        elif request.method == 'DELETE':
            entry_id = request.args.get('id')
            conn.execute("DELETE FROM whitelist WHERE id = ?", (entry_id,))
            conn.commit()
            conn.close()
            return jsonify({'success': True})
    
    except Exception as e:
        print(f"Whitelist API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/history')
def get_analysis_history():
    """Get analysis history"""
    try:
        conn = detector.get_db_connection()
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        offset = (page - 1) * per_page
        
        entries = conn.execute(
            "SELECT * FROM email_analysis ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (per_page, offset)
        ).fetchall()
        
        total = conn.execute("SELECT COUNT(*) FROM email_analysis").fetchone()[0]
        conn.close()
        
        return jsonify({
            'entries': [dict(entry) for entry in entries],
            'total': total,
            'page': page,
            'per_page': per_page
        })
    except Exception as e:
        print(f"History API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
def get_stats():
    """Get dashboard statistics"""
    try:
        conn = detector.get_db_connection()
        
        total_analyzed = conn.execute("SELECT COUNT(*) FROM email_analysis").fetchone()[0]
        safe_count = conn.execute("SELECT COUNT(*) FROM email_analysis WHERE verdict = 'SAFE'").fetchone()[0]
        suspicious_count = conn.execute("SELECT COUNT(*) FROM email_analysis WHERE verdict = 'SUSPICIOUS'").fetchone()[0]
        unsafe_count = conn.execute("SELECT COUNT(*) FROM email_analysis WHERE verdict = 'UNSAFE'").fetchone()[0]
        whitelist_count = conn.execute("SELECT COUNT(*) FROM whitelist").fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'total_analyzed': total_analyzed,
            'safe_count': safe_count,
            'suspicious_count': suspicious_count,
            'unsafe_count': unsafe_count,
            'whitelist_count': whitelist_count
        })
    except Exception as e:
        print(f"Stats API error: {e}")
        return jsonify({'error': str(e)}), 500

# Serve Chrome extension files
@app.route('/extension/<path:filename>')
def serve_extension(filename):
    return send_from_directory('extension', filename)

if __name__ == '__main__':
    # Ensure database is set up
    if not os.path.exists('data/phishing_detector.db'):
        try:
            from scripts.setup_database import setup_database
            setup_database()
        except Exception as e:
            print(f"Database setup failed: {e}")
    
    print("🚀 Starting Phishing Email Detector Backend...")
    print("📊 Dashboard: http://localhost:5000")
    print("🔌 API: http://localhost:5000/api/")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
