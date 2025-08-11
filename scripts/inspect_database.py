import sqlite3
import json
from datetime import datetime

def inspect_database():
    """Inspect the database contents and structure"""
    
    db_path = "data/phishing_detector.db"
    
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        print("🔍 PhishNet Database Inspection")
        print("=" * 50)
        
        # Check if database exists and tables are created
        tables = cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        print(f"\n📋 Tables found: {[t['name'] for t in tables]}")
        
        if not tables:
            print("❌ No tables found! Run setup_database.py first.")
            return
        
        # Check email_analysis table
        if any(t['name'] == 'email_analysis' for t in tables):
            print("\n📧 EMAIL_ANALYSIS TABLE:")
            
            # Get schema
            schema = cur.execute("PRAGMA table_info(email_analysis)").fetchall()
            print("   Schema:")
            for col in schema:
                print(f"     - {col['name']}: {col['type']}")
            
            # Get total count
            total = cur.execute("SELECT COUNT(*) FROM email_analysis").fetchone()[0]
            print(f"\n   📊 Total entries: {total}")
            
            if total > 0:
                # Get counts by verdict
                verdicts = cur.execute("""
                    SELECT verdict, COUNT(*) as count 
                    FROM email_analysis 
                    GROUP BY verdict
                """).fetchall()
                
                print("   📈 Breakdown by verdict:")
                for v in verdicts:
                    print(f"     - {v['verdict']}: {v['count']}")
                
                # Get recent entries
                recent = cur.execute("""
                    SELECT email_id, sender_email, sender_domain, subject, score, verdict,
                           datetime(timestamp, 'localtime') as local_time,
                           CASE 
                               WHEN sender_email = '' OR sender_email IS NULL THEN 'MISSING_SENDER'
                               WHEN sender_domain = '' OR sender_domain IS NULL THEN 'MISSING_DOMAIN'
                               WHEN subject = '' OR subject IS NULL THEN 'MISSING_SUBJECT'
                               ELSE 'OK'
                           END as data_status
                    FROM email_analysis 
                    ORDER BY timestamp DESC 
                    LIMIT 10
                """).fetchall()
                
                print(f"\n   📋 Recent 10 entries:")
                for i, entry in enumerate(recent, 1):
                    print(f"     {i}. [{entry['data_status']}] {entry['local_time']}")
                    print(f"        From: {entry['sender_email'] or 'MISSING'}")
                    print(f"        Domain: {entry['sender_domain'] or 'MISSING'}")
                    print(f"        Subject: {(entry['subject'] or 'MISSING')[:50]}...")
                    print(f"        Score: {entry['score']}% | Verdict: {entry['verdict']}")
                    print()
                
                # Check for data quality issues
                missing_sender = cur.execute("SELECT COUNT(*) FROM email_analysis WHERE sender_email = '' OR sender_email IS NULL").fetchone()[0]
                missing_domain = cur.execute("SELECT COUNT(*) FROM email_analysis WHERE sender_domain = '' OR sender_domain IS NULL").fetchone()[0]
                missing_subject = cur.execute("SELECT COUNT(*) FROM email_analysis WHERE subject = '' OR subject IS NULL").fetchone()[0]
                
                print("   ⚠️  Data Quality Issues:")
                print(f"     - Missing sender: {missing_sender}")
                print(f"     - Missing domain: {missing_domain}")
                print(f"     - Missing subject: {missing_subject}")
        
        # Check whitelist table
        if any(t['name'] == 'whitelist' for t in tables):
            whitelist_count = cur.execute("SELECT COUNT(*) FROM whitelist").fetchone()[0]
            print(f"\n🛡️  WHITELIST TABLE: {whitelist_count} entries")
            
            if whitelist_count > 0:
                types = cur.execute("SELECT type, COUNT(*) as count FROM whitelist GROUP BY type").fetchall()
                for t in types:
                    print(f"     - {t['type']}: {t['count']}")
        
        conn.close()
        
        print("\n" + "=" * 50)
        print("💡 Tips:")
        print("- If entries are missing, check Chrome extension console for errors")
        print("- If data is incomplete, enable debug mode: PHISHNET_DEBUG=1")
        print("- Use /api/debug/recent-analyses to see raw database data")
        
    except Exception as e:
        print(f"❌ Database inspection failed: {e}")

if __name__ == "__main__":
    inspect_database()
