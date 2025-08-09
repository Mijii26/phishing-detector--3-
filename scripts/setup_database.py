import sqlite3
import os

def setup_database():
    """Initialize the SQLite database with required tables"""
    
    # Create data directory if it doesn't exist
    os.makedirs('data', exist_ok=True)
    
    conn = sqlite3.connect('data/phishing_detector.db')
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
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
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            value TEXT UNIQUE,
            added_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            notes TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS domain_reputation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE,
            reputation_score INTEGER,
            is_malicious BOOLEAN,
            last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert some default whitelist entries
    default_whitelist = [
        ('domain', 'gmail.com', 'Google Gmail'),
        ('domain', 'outlook.com', 'Microsoft Outlook'),
        ('domain', 'yahoo.com', 'Yahoo Mail'),
        ('domain', 'apple.com', 'Apple'),
        ('domain', 'microsoft.com', 'Microsoft'),
        ('domain', 'google.com', 'Google'),
        ('keyword', 'unsubscribe', 'Legitimate unsubscribe links'),
        ('keyword', 'privacy policy', 'Privacy policy links')
    ]
    
    for item_type, value, notes in default_whitelist:
        cursor.execute('''
            INSERT OR IGNORE INTO whitelist (type, value, notes) 
            VALUES (?, ?, ?)
        ''', (item_type, value, notes))
    
    conn.commit()
    conn.close()
    print("Database setup completed successfully!")

if __name__ == "__main__":
    setup_database()
