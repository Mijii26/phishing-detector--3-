"""PhishNet - Enhanced version with better data extraction and storage"""
import os
import re
import json
import time
import socket
import random
import string
import sqlite3
import hashlib
import requests
import tldextract
import dns.resolver
from datetime import datetime
from urllib.parse import urlparse, unquote
from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS

# Optional libs with graceful fallback
try:
    from textstat import flesch_reading_ease
    TEXTSTAT_AVAILABLE = True
except Exception:
    TEXTSTAT_AVAILABLE = False
    def flesch_reading_ease(text):
        return 50

try:
    import language_tool_python
    LANGUAGE_TOOL_AVAILABLE = True
except Exception:
    LANGUAGE_TOOL_AVAILABLE = False
    class MockLanguageTool:
        def check(self, text):
            return []
        def close(self):
            pass
    class MockLanguageToolModule:
        def LanguageTool(self, lang):
            return MockLanguageTool()
    language_tool_python = MockLanguageToolModule()

try:
    import whois
    WHOIS_AVAILABLE = True
except Exception:
    WHOIS_AVAILABLE = False

# Load .env if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Config
DEBUG = os.getenv("PHISHNET_DEBUG", "0").lower() in ("1", "true", "yes")
ENABLE_EXTERNAL_CHECKS = os.getenv("PHISHNET_ENABLE_EXTERNAL", "1").lower() not in ("0", "false", "no")
DB_PATH = os.getenv("PHISHNET_DB", "data/phishing_detector.db")

# Ensure data directory exists
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def log(*args, **kwargs):
    if DEBUG:
        print(*args, **kwargs)

# --- Database helpers and schema creation ---
def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn

def ensure_db():
    conn = get_db_connection()
    cur = conn.cursor()
    
    # whitelist table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        value TEXT NOT NULL UNIQUE,
        notes TEXT,
        added_date DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    
    # email_analysis table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS email_analysis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email_id TEXT UNIQUE,
        sender_email TEXT,
        sender_domain TEXT,
        subject TEXT,
        content_preview TEXT,
        urls TEXT,
        score INTEGER,
        verdict TEXT,
        analysis_details TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    
    conn.commit()
    conn.close()

ensure_db()

# --- Unique email ID generator ---
def generate_unique_email_id(email_data):
    """Generate a unique ID for each email analysis"""
    sender = (email_data.get('sender') or '')[:64].replace(' ', '')
    subj = (email_data.get('subject') or '')[:40].replace(' ', '')
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    base = f"{sender}_{subj}_{ts}_{rand}"
    return hashlib.sha256(base.encode()).hexdigest()

class PhishingDetector:
    def __init__(self):
        self.db_path = DB_PATH
        self.domain_cache = {}
        self.domain_cache_ttl = 24 * 3600
        
        # Enhanced phishing patterns
        self.phishing_patterns = [
            r'urgent.{0,30}action', r'verify.{0,30}(account|identity|information)',
            r'suspended.{0,30}account', r'click.{0,30}here', r'limited.{0,30}time',
            r'congratulations.{0,30}(winner|you)', r'claim.{0,30}prize',
            r'tax.{0,30}refund', r'security.{0,30}alert', r'unusual.{0,30}activity',
            r'confirm.{0,30}(identity|account|payment)', r'update.{0,30}(payment|credentials)',
            r'password.{0,30}reset', r'login.{0,30}now', r'gift.{0,30}card',
            r'crypto.{0,30}investment', r'wire.{0,30}transfer', r'\b2fa\b.{0,10}disable',
            r'log in to (your )?account', r'update (your )?account (now|immediately)?'
        ]
        
        self.suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click', '.download'}
        self.known_brands = {
            'paypal.com','google.com','microsoft.com','apple.com','amazon.com',
            'facebook.com','vercel.com','netflix.com','bankofamerica.com','chase.com',
            'wellsfargo.com','citibank.com','github.com'
        }
        self.shorteners = {'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','cutt.ly','rebrand.ly'}
        
        # Initialize grammar tool
        if LANGUAGE_TOOL_AVAILABLE:
            try:
                self.grammar_tool = language_tool_python.LanguageTool('en-US')
                log("✅ Grammar tool initialized")
            except Exception as e:
                log("⚠️ Grammar tool init failed:", e)
                self.grammar_tool = None
        else:
            self.grammar_tool = None
        
        # External API keys
        self.gsb_key = os.getenv('GOOGLE_SAFE_BROWSING_KEY')
        self.vt_key = os.getenv('VIRUSTOTAL_API_KEY') or os.getenv('VT_API_KEY')
        self.phishtank_key = os.getenv('PHISHTANK_APP_KEY')
        self.abuseipdb_key = os.getenv('ABUSEIPDB_KEY') or os.getenv('ABUSEIPDB_API_KEY')
        self.urlscan_key = os.getenv('URLSCAN_API_KEY') or os.getenv('URLSCAN_KEY')
        self.urlhaus_enabled = os.getenv('URLHAUS_ENABLED', '').lower() in ('1','true','yes')

    def _is_ip(self, host: str) -> bool:
        if not host:
            return False
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host):
            return True
        return ':' in host and not host.startswith('xn--')

    def _lev_ratio(self, a: str, b: str) -> float:
        a, b = (a or '').lower(), (b or '').lower()
        m, n = len(a), len(b)
        if m == 0 or n == 0:
            return 0.0
        dp = [[0]*(n+1) for _ in range(m+1)]
        for i in range(m+1): dp[i][0] = i
        for j in range(n+1): dp[0][j] = j
        for i in range(1,m+1):
            for j in range(1,n+1):
                cost = 0 if a[i-1] == b[j-1] else 1
                dp[i][j] = min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+cost)
        dist = dp[m][n]
        return 1.0 - dist / max(m,n)

    def _domain_age_days(self, domain: str):
        if not domain:
            return None
        if WHOIS_AVAILABLE:
            try:
                w = whois.whois(domain)
                created = w.creation_date
                if isinstance(created, list):
                    created = min([d for d in created if hasattr(d,'year')], default=None)
                if hasattr(created,'year'):
                    return (datetime.utcnow() - created.replace(tzinfo=None)).days
            except Exception:
                pass
        return None

    def _has_spf(self, domain: str) -> bool:
        try:
            answers = dns.resolver.resolve(domain, 'TXT', raise_on_no_answer=False)
            for r in answers:
                try:
                    txt = ''.join(r.strings).decode('utf-8') if hasattr(r,'strings') else str(r)
                except Exception:
                    txt = str(r)
                if 'v=spf1' in txt.lower():
                    return True
        except Exception:
            pass
        return False

    def _dmarc_policy(self, domain: str):
        try:
            d = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(d, 'TXT', raise_on_no_answer=False)
            for r in answers:
                try:
                    txt = ''.join(r.strings).decode('utf-8') if hasattr(r,'strings') else str(r)
                except Exception:
                    txt = str(r)
                if 'v=dmarc1' in txt.lower():
                    m = re.search(r'\bp=([a-zA-Z]+)', txt, re.IGNORECASE)
                    return m.group(1).lower() if m else 'none'
        except Exception:
            pass
        return None

    def _mx_exists(self, domain: str) -> bool:
        try:
            answers = dns.resolver.resolve(domain, 'MX', raise_on_no_answer=False)
            return answers is not None and len(answers) > 0
        except Exception:
            return False

    def _looks_punycode(self, domain: str) -> bool:
        return 'xn--' in (domain or '')

    def _similar_to_brand(self, domain: str) -> bool:
        try:
            ext = tldextract.extract(domain)
            sld = ext.domain
            for b in self.known_brands:
                brand_sld = tldextract.extract(b).domain
                if sld == brand_sld and ext.suffix != tldextract.extract(b).suffix:
                    return True
                ratio = self._lev_ratio(sld, brand_sld)
                if ratio >= 0.85 and sld != brand_sld:
                    return True
        except Exception:
            pass
        return False

    def _check_external_reputation(self, url: str, domain: str):
        score_adj = 0
        issues = []
        if not ENABLE_EXTERNAL_CHECKS:
            return score_adj, issues

        # Google Safe Browsing
        if self.gsb_key:
            try:
                payload = {
                    "client":{"clientId":"phishnet","clientVersion":"1.0"},
                    "threatInfo":{"threatTypes":["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
                                  "platformTypes":["ANY_PLATFORM"], "threatEntryTypes":["URL"],
                                  "threatEntries":[{"url": url}]}
                }
                resp = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.gsb_key}", json=payload, timeout=8)
                if resp.ok and resp.json().get("matches"):
                    score_adj -= 60
                    issues.append("Flagged by Google Safe Browsing")
            except Exception:
                pass

        return score_adj, issues

    def check_domain_reputation(self, domain: str):
        if not domain:
            return 40, ["No domain provided"]
        
        # Clean domain
        try:
            domain = domain.split('@')[-1].split(':')[0].strip().lower()
        except Exception:
            domain = str(domain).strip().lower()
        
        log(f"🔍 Checking domain reputation for: {domain}")
        
        now = time.time()
        cache = self.domain_cache.get(domain)
        if cache and (now - cache[2]) < self.domain_cache_ttl:
            log(f"📋 Using cached result for {domain}")
            return cache[0], cache[1]

        score = 100
        issues = []

        # Check if domain resolves
        try:
            socket.gethostbyname(domain)
            resolves = True
            log(f"✅ Domain {domain} resolves")
        except Exception:
            resolves = False
            log(f"❌ Domain {domain} does not resolve")

        if not resolves:
            score -= 50
            issues.append("Domain does not resolve")
            self.domain_cache[domain] = (max(0,score), issues, now)
            return max(0,score), issues

        # Check MX record
        if not self._mx_exists(domain):
            score -= 10
            issues.append("No MX record found")

        # Check SPF
        if not self._has_spf(domain):
            score -= 8
            issues.append("No SPF record")

        # Check DMARC
        policy = self._dmarc_policy(domain)
        if policy is None:
            score -= 8
            issues.append("No DMARC record")
        elif policy == 'none':
            score -= 4
            issues.append("DMARC policy = none")

        # Check TLD
        ext = tldextract.extract(domain)
        suffix = f".{ext.suffix}" if ext.suffix else ""
        if suffix in self.suspicious_tlds:
            score -= 20
            issues.append("Suspicious TLD")

        # Other checks
        if self._is_ip(domain):
            score -= 25
            issues.append("IP-based domain")

        if self._looks_punycode(domain):
            score -= 20
            issues.append("Punycode domain")

        if len(domain) > 35:
            score -= 8
            issues.append("Very long domain")
        elif len(domain) > 25:
            score -= 4
            issues.append("Long domain")

        if self._similar_to_brand(domain):
            score -= 25
            issues.append("Possible typosquatting / brand impersonation")

        # Domain age
        age_days = self._domain_age_days(domain)
        if age_days is not None:
            if age_days < 90:
                score -= 15
                issues.append("Newly created domain (<90d)")
            elif age_days < 365:
                score -= 8
                issues.append("Young domain (<1y)")

        score = max(0, score)
        self.domain_cache[domain] = (score, issues, now)
        log(f"📊 Domain {domain} score: {score}, issues: {len(issues)}")
        return score, issues

    def analyze_content(self, content):
        if not content:
            return 50, ["No content"]
        
        text = content.strip()
        score = 100
        issues = []

        # Check phishing patterns
        matches = 0
        for p in self.phishing_patterns:
            if re.search(p, text, flags=re.IGNORECASE):
                matches += 1

        if matches > 0:
            score -= min(60, matches * 12)
            issues.append(f"Found {matches} phishing pattern(s)")

        # Grammar check
        if self.grammar_tool:
            try:
                g = self.grammar_tool.check(text[:2000])
                cnt = len(g)
                if cnt > 6:
                    score -= min(20, cnt * 2)
                    issues.append(f"Grammar/spelling issues: {cnt}")
            except Exception as e:
                log("Grammar check error:", e)

        # Reading ease
        if TEXTSTAT_AVAILABLE:
            try:
                ease = flesch_reading_ease(text)
                if ease < 25:
                    score -= 8
                    issues.append("Very low reading ease")
            except Exception:
                pass

        # Urgency language
        urgency_words = ['urgent','immediate','asap','hurry','quick','now','today','immediately']
        urgency_count = sum(1 for w in urgency_words if w in text.lower())
        if urgency_count >= 2:
            score -= 10
            issues.append(f"Urgency language ({urgency_count})")

        # Multiple links
        link_count = len(re.findall(r'https?://', text, flags=re.IGNORECASE))
        if link_count >= 3:
            score -= 8
            issues.append(f"Multiple links ({link_count})")

        log(f"📝 Content analysis score: {score}, issues: {len(issues)}")
        return max(0, score), issues

    def extract_urls(self, text):
        if not text:
            return []
        
        urls = re.findall(r'https?://[^\s<>"\'\)\]]+', text, flags=re.IGNORECASE)
        hrefs = re.findall(r'href=[\'"]([^\'"]+)[\'"]', text, flags=re.IGNORECASE)
        found = set()
        
        for u in urls + hrefs:
            try:
                u_dec = unquote(u).strip()
            except Exception:
                u_dec = u.strip()
            if u_dec.lower().startswith('mailto:'):
                continue
            if not re.match(r'^https?://', u_dec, flags=re.IGNORECASE):
                continue
            found.add(u_dec)
        
        return list(found)

    def analyze_urls(self, urls):
        if not urls:
            return 100, []

        overall_issues = []
        per_scores = []

        for url in urls:
            url_score = 100
            try:
                parsed = urlparse(url)
                scheme = (parsed.scheme or '').lower()
                host = (parsed.hostname or '').lower()

                # Check domain reputation
                d_score, d_issues = self.check_domain_reputation(host)
                overall_issues.extend([f"{host}: {i}" for i in d_issues])
                if d_score < 80:
                    url_score -= min(40, 100 - d_score)

                # HTTPS check
                if scheme != 'https':
                    url_score -= 8
                    overall_issues.append(f"{host}: Non-HTTPS link")

                # Other URL checks
                if '@' in url:
                    url_score -= 12
                    overall_issues.append(f"{host}: @ in URL (obfuscation)")

                if self._is_ip(host):
                    url_score -= 12
                    overall_issues.append(f"{host}: IP used instead of domain")

                if any(s in host for s in self.shorteners):
                    url_score -= 18
                    overall_issues.append(f"{host}: URL shortener detected")

                # External reputation check
                adj, rep_issues = self._check_external_reputation(url, host)
                url_score += adj
                overall_issues.extend(rep_issues)

            except Exception as e:
                log("URL analyze exception:", e)
                url_score -= 30
                overall_issues.append(f"Malformed URL: {url}")

            per_scores.append(max(0, url_score))

        final = max(0, min(per_scores))
        log(f"🔗 URL analysis score: {final}, issues: {len(overall_issues)}")
        return final, overall_issues

    def check_whitelist(self, sender_email, sender_domain, content):
        try:
            conn = get_db_connection()
            
            # Check sender email
            row = conn.execute("SELECT * FROM whitelist WHERE type='email' AND value=?", (sender_email,)).fetchone()
            if row:
                conn.close()
                return True, "Sender email whitelisted"
            
            # Check sender domain
            row = conn.execute("SELECT * FROM whitelist WHERE type='domain' AND value=?", (sender_domain,)).fetchone()
            if row:
                conn.close()
                return True, "Sender domain whitelisted"
            
            # Check keywords
            rows = conn.execute("SELECT value FROM whitelist WHERE type='keyword'").fetchall()
            for r in rows:
                if r['value'].lower() in (content or '').lower():
                    conn.close()
                    return True, f"Whitelisted keyword found: {r['value']}"
            
            conn.close()
        except Exception as e:
            log("Whitelist check failed:", e)
        
        return False, ""

    def analyze_email(self, email_data):
        try:
            sender = (email_data.get('sender') or '').strip()
            subject = (email_data.get('subject') or '').strip()
            content = (email_data.get('content') or '').strip()
            combined = " ".join([subject, content]).strip()

            log(f"🔍 Analyzing email from: {sender}")
            log(f"📧 Subject: {subject[:50]}...")
            log(f"📝 Content length: {len(content)}")

            # Extract sender domain
            sender_domain = ''
            if '@' in sender:
                sender_domain = sender.split('@')[-1].lower().split(':')[0]
            
            log(f"🌐 Sender domain: {sender_domain}")

            # Check whitelist
            wh, reason = self.check_whitelist(sender, sender_domain, combined)
            if wh:
                log(f"✅ Email whitelisted: {reason}")
                return {'score': 100, 'verdict': 'SAFE', 'reason': reason, 'details': {'whitelisted': True}}

            # Extract URLs
            urls = self.extract_urls(content)
            log(f"🔗 Found {len(urls)} URLs")

            # Perform analysis
            domain_score, domain_issues = self.check_domain_reputation(sender_domain) if sender_domain else (40, ["No sender domain"])
            content_score, content_issues = self.analyze_content(combined)
            url_score, url_issues = self.analyze_urls(urls)

            log(f"📊 Scores -> domain: {domain_score}, content: {content_score}, urls: {url_score}")

            # Calculate final score
            final_score = int((domain_score * 0.35) + (content_score * 0.45) + (url_score * 0.20))
            verdict = 'SAFE' if final_score >= 70 else ('SUSPICIOUS' if final_score >= 50 else 'UNSAFE')

            # Compile all issues
            all_issues = domain_issues + content_issues + url_issues

            details = {
                'domain_score': domain_score, 'domain_issues': domain_issues,
                'content_score': content_score, 'content_issues': content_issues,
                'url_score': url_score, 'url_issues': url_issues,
                'urls_found': urls, 'sender_domain': sender_domain,
                'issues': all_issues
            }

            analysis_result = {'score': final_score, 'verdict': verdict, 'details': details}

            log(f"✅ Analysis complete: {verdict} ({final_score}%)")

            # Store in database
            self.store_analysis(email_data, analysis_result)

            return analysis_result

        except Exception as e:
            log(f"❌ Analysis error: {e}")
            return {'score': 50, 'verdict': 'ERROR', 'details': {'error': str(e)}}

    def store_analysis(self, email_data, analysis_result, max_retries=5):
        """Store analysis with enhanced debugging and validation"""
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
        
            # Extract and validate data with better fallbacks
            sender_email = (email_data.get('sender') or '').strip()
            subject = (email_data.get('subject') or '').strip()
            content = (email_data.get('content') or '').strip()
        
            # Enhanced sender domain extraction
            sender_domain = analysis_result['details'].get('sender_domain', '')
            if not sender_domain and '@' in sender_email:
                try:
                    sender_domain = sender_email.split('@')[-1].lower().split(':')[0]
                except Exception:
                    sender_domain = 'unknown'
            elif not sender_domain:
                sender_domain = 'unknown'
        
            log(f"💾 STORAGE DEBUG:")
            log(f"   📧 Sender: '{sender_email}'")
            log(f"   🌐 Domain: '{sender_domain}'") 
            log(f"   📝 Subject: '{subject[:50]}...'")
            log(f"   📊 Score: {analysis_result['score']}")
            log(f"   ⚖️  Verdict: {analysis_result['verdict']}")
        
            # Generate unique email ID
            email_id = generate_unique_email_id(email_data)
            log(f"   🆔 Email ID: {email_id}")
        
            # Prepare data for insertion
            urls_json = json.dumps(analysis_result['details'].get('urls_found', []))
            details_json = json.dumps(analysis_result['details'])
        
            # Insert with detailed error handling
            try:
                cur.execute('''
                    INSERT INTO email_analysis
                    (email_id, sender_email, sender_domain, subject, content_preview, urls, score, verdict, analysis_details, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                ''', (
                    email_id,
                    sender_email,
                    sender_domain,
                    subject[:200] if subject else '',
                    content[:500] if content else '',
                    urls_json,
                    analysis_result['score'],
                    analysis_result['verdict'],
                    details_json
                ))
            
                conn.commit()
            
                # Verify insertion
                verify = cur.execute("SELECT COUNT(*) FROM email_analysis WHERE email_id = ?", (email_id,)).fetchone()[0]
                if verify > 0:
                    log(f"✅ STORAGE SUCCESS: Email stored and verified in database")
                
                    # Get total count for verification
                    total = cur.execute("SELECT COUNT(*) FROM email_analysis").fetchone()[0]
                    log(f"📊 Total emails in database: {total}")
                else:
                    log(f"❌ STORAGE FAILED: Email not found after insertion")
                
            except sqlite3.IntegrityError as e:
                log(f"⚠️ STORAGE INTEGRITY ERROR: {e}")
                # Try with a different ID
                email_id = f"{email_id}_{int(time.time())}"
                cur.execute('''
                    INSERT INTO email_analysis
                    (email_id, sender_email, sender_domain, subject, content_preview, urls, score, verdict, analysis_details, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                ''', (
                    email_id, sender_email, sender_domain, subject[:200] if subject else '',
                    content[:500] if content else '', urls_json, analysis_result['score'],
                    analysis_result['verdict'], details_json
                ))
                conn.commit()
                log(f"✅ STORAGE SUCCESS: Stored with modified ID: {email_id}")
            
        except Exception as e:
            log(f"❌ STORAGE ERROR: {e}")
            import traceback
            log(f"📋 Full traceback: {traceback.format_exc()}")
        finally:
            if conn:
                conn.close()

# Initialize detector
detector = PhishingDetector()

# Flask app
app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    try:
        return render_template('index.html')
    except Exception:
        return "PhishNet API"

@app.route('/api/analyze', methods=['POST'])
def analyze_email():
    try:
        email_data = request.json
        if not email_data:
            return jsonify({'error': 'No email data provided'}), 400
        
        log(f"📨 API received email data: {email_data.get('sender', 'No sender')}")
        result = detector.analyze_email(email_data)
        return jsonify(result)
    except Exception as e:
        log(f"❌ API analyze error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/whitelist', methods=['GET', 'POST', 'DELETE'])
def manage_whitelist():
    try:
        conn = get_db_connection()
        
        if request.method == 'GET':
            rows = conn.execute("SELECT * FROM whitelist ORDER BY type, value").fetchall()
            conn.close()
            return jsonify([dict(r) for r in rows])
        
        elif request.method == 'POST':
            data = request.json or {}
            conn.execute("INSERT INTO whitelist (type, value, notes) VALUES (?, ?, ?)", 
                        (data['type'], data['value'], data.get('notes','')))
            conn.commit()
            conn.close()
            return jsonify({'success': True})
        
        elif request.method == 'DELETE':
            entry_id = request.args.get('id')
            conn.execute("DELETE FROM whitelist WHERE id=?", (entry_id,))
            conn.commit()
            conn.close()
            return jsonify({'success': True})
            
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Entry already exists'}), 400
    except Exception as e:
        log(f"❌ Whitelist API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/history')
def get_analysis_history():
    try:
        conn = get_db_connection()
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        offset = (page - 1) * per_page
        
        rows = conn.execute(
            "SELECT * FROM email_analysis ORDER BY timestamp DESC LIMIT ? OFFSET ?", 
            (per_page, offset)
        ).fetchall()
        
        total = conn.execute("SELECT COUNT(*) FROM email_analysis").fetchone()[0]
        conn.close()
        
        log(f"📋 History API returning {len(rows)} entries (total: {total})")
        return jsonify({
            'entries': [dict(r) for r in rows], 
            'total': total, 
            'page': page, 
            'per_page': per_page
        })
    except Exception as e:
        log(f"❌ History API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
def get_stats():
    try:
        conn = get_db_connection()
        total = conn.execute("SELECT COUNT(*) FROM email_analysis").fetchone()[0]
        safe = conn.execute("SELECT COUNT(*) FROM email_analysis WHERE verdict='SAFE'").fetchone()[0]
        susp = conn.execute("SELECT COUNT(*) FROM email_analysis WHERE verdict='SUSPICIOUS'").fetchone()[0]
        unsafe = conn.execute("SELECT COUNT(*) FROM email_analysis WHERE verdict='UNSAFE'").fetchone()[0]
        whitelist_count = conn.execute("SELECT COUNT(*) FROM whitelist").fetchone()[0]
        conn.close()
        
        return jsonify({
            'total_analyzed': total, 
            'safe_count': safe, 
            'suspicious_count': susp, 
            'unsafe_count': unsafe, 
            'whitelist_count': whitelist_count
        })
    except Exception as e:
        log(f"❌ Stats API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/recent-analyses')
def debug_recent_analyses():
    """Debug endpoint to see recent database entries with full details"""
    try:
        conn = get_db_connection()
        rows = conn.execute("""
            SELECT email_id, sender_email, sender_domain, subject, score, verdict, timestamp,
                   LENGTH(content_preview) as content_length,
                   LENGTH(analysis_details) as details_length
            FROM email_analysis 
            ORDER BY timestamp DESC 
            LIMIT 50
        """).fetchall()
        conn.close()
        
        return jsonify({
            'total_found': len(rows),
            'entries': [dict(r) for r in rows]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/database-info')
def debug_database_info():
    """Debug endpoint to show database schema and counts"""
    try:
        conn = get_db_connection()
        
        # Get table info
        schema = conn.execute("PRAGMA table_info(email_analysis)").fetchall()
        
        # Get counts by verdict
        verdicts = conn.execute("""
            SELECT verdict, COUNT(*) as count 
            FROM email_analysis 
            GROUP BY verdict
        """).fetchall()
        
        # Get recent entries with more details
        recent = conn.execute("""
            SELECT email_id, sender_email, sender_domain, subject, score, verdict, 
                   datetime(timestamp, 'localtime') as local_time,
                   CASE 
                       WHEN sender_email = '' THEN 'MISSING_SENDER'
                       WHEN sender_domain = '' THEN 'MISSING_DOMAIN' 
                       WHEN subject = '' THEN 'MISSING_SUBJECT'
                       ELSE 'OK'
                   END as data_status
            FROM email_analysis 
            ORDER BY timestamp DESC 
            LIMIT 20
        """).fetchall()
        
        conn.close()
        
        return jsonify({
            'schema': [dict(r) for r in schema],
            'verdict_counts': [dict(r) for r in verdicts],
            'recent_entries': [dict(r) for r in recent],
            'database_path': DB_PATH
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/test-storage', methods=['POST'])
def debug_test_storage():
    """Test endpoint to manually store a test email"""
    try:
        test_email = {
            'sender': 'test@gmail.com',
            'subject': 'Test Email from Debug Endpoint',
            'content': 'This is a test email to verify storage is working correctly.'
        }
        
        log("🧪 Debug: Testing email storage...")
        result = detector.analyze_email(test_email)
        
        return jsonify({
            'test_email': test_email,
            'analysis_result': result,
            'message': 'Test email analyzed and should be stored'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/extension/<path:filename>')
def serve_extension(filename):
    return send_from_directory('extension', filename)

if __name__ == "__main__":
    log("🚀 Starting PhishNet with enhanced debugging...")
    log(f"📊 Debug mode: {DEBUG}")
    log(f"🔗 External checks: {ENABLE_EXTERNAL_CHECKS}")
    
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 5000)), debug=False)
