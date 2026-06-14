#!/usr/bin/env python3
"""
WordPress Database Auditor for OptinMonster Supply Chain Attack
This script audits a WordPress database for rogue admin accounts (e.g. developer_api1, dev_xxxxxx).
It supports:
1. Scanning a SQL dump file (--dump)
2. Scanning a live MySQL database (--live) by parsing wp-config.php or using CLI args

Exit codes:
  0: Clean (no rogue accounts found)
  1: Compromised (rogue administrator account found)
  2: Execution error
"""

import os
import sys
import re
import argparse

# Targets defined in research
FIXED_USER = "developer_api1"
FIXED_EMAIL = "customer1usx@gmail.com"

# Regular expression matching developer_api1 or dev_xxxxxx
USER_PATTERN = re.compile(r'\bdeveloper_api1\b|\bdev_[a-zA-Z0-9]{6}\b')
EMAIL_PATTERN = re.compile(r'\bcustomer1usx@gmail\.com\b|\bdev_[a-zA-Z0-9]{6}@gmail\.com\b')

def parse_wp_config(wp_config_path):
    """Parse wp-config.php to extract DB connection info and table prefix."""
    config = {
        "DB_NAME": "wordpress",
        "DB_USER": "root",
        "DB_PASSWORD": "",
        "DB_HOST": "localhost",
        "prefix": "wp_"
    }
    
    if not os.path.exists(wp_config_path):
        return config
        
    try:
        with open(wp_config_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        # Extract constants define('DB_NAME', 'value')
        for key in ["DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST"]:
            match = re.search(rf"define\(\s*['\"]{key}['\"]\s*,\s*['\"](.*?)['\"]\s*\);", content)
            if match:
                config[key] = match.group(1)
                
        # Extract table prefix $table_prefix = 'wp_';
        prefix_match = re.search(r"\$table_prefix\s*=\s*['\"](.*?)['\"]\s*;", content)
        if prefix_match:
            config["prefix"] = prefix_match.group(1)
            
    except (IOError, OSError, KeyError, IndexError, ValueError) as e:
        print(f"[-] Warning: Failed to parse wp-config.php: {e}", file=sys.stderr)
        return config
        
    return config

def audit_sql_dump(dump_path, prefix="wp_"):
    """Scan a SQL dump file line-by-line for inserts or queries containing rogue accounts."""
    compromised = False
    users_table = f"{prefix}users"
    
    if not os.path.exists(dump_path):
        print(f"[-] SQL Dump file does not exist: {dump_path}", file=sys.stderr)
        return 2

    print(f"[*] Auditing SQL dump file: {dump_path} (looking for users table: {users_table})")
    
    try:
        with open(dump_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_no, line in enumerate(f, 1):
                # We specifically check lines mentioning users table or raw patterns
                if users_table in line or "users" in line or FIXED_USER in line or FIXED_EMAIL in line:
                    user_matches = USER_PATTERN.findall(line)
                    email_matches = EMAIL_PATTERN.findall(line)
                    
                    if user_matches or email_matches:
                        print(f"[!] COMPROMISED: Found rogue account indicators at line {line_no}:")
                        if user_matches:
                            print(f"    - Matches username pattern: {user_matches}")
                        if email_matches:
                            print(f"    - Matches email pattern: {email_matches}")
                        compromised = True
                        
    except (IOError, OSError) as e:
        print(f"[-] Error reading SQL dump: {e}", file=sys.stderr)
        return 2
        
    return 1 if compromised else 0

def audit_live_db(config, host=None, user=None, password=None, database=None, port=None):
    """Query the WordPress database for rogue admins."""
    try:
        import mysql.connector
    except ImportError:
        print("[-] Error: 'mysql-connector-python' is required for live database audits.", file=sys.stderr)
        print("    Please install it using 'pip install mysql-connector-python' or scan a SQL dump instead.", file=sys.stderr)
        return 2

    db_host = host or config["DB_HOST"]
    db_user = user or config["DB_USER"]
    db_pass = password or config["DB_PASSWORD"]
    db_name = database or config["DB_NAME"]
    
    db_port = 3306
    if port:
        db_port = int(port)
    elif ":" in db_host:
        parts = db_host.split(":")
        db_host = parts[0]
        db_port = int(parts[1])

    print(f"[*] Connecting to live database {db_name} on {db_host}:{db_port}...")
    
    try:
        conn = mysql.connector.connect(
            host=db_host,
            user=db_user,
            password=db_pass,
            database=db_name,
            port=db_port,
            connect_timeout=5
        )
        cursor = conn.cursor(dictionary=True)
    except Exception as e:
        print(f"[-] Database connection failure: {e}", file=sys.stderr)
        return 2

    users_table = f"{config['prefix']}users"
    print(f"[*] Querying table: {users_table}")
    
    query = f"""
        SELECT ID, user_login, user_email, user_registered 
        FROM {users_table} 
        WHERE user_login = %s 
           OR user_email = %s 
           OR user_login LIKE 'dev_%' 
           OR user_email LIKE 'dev_%@gmail.com'
    """
    
    try:
        cursor.execute(query, (FIXED_USER, FIXED_EMAIL))
        results = cursor.fetchall()
        
        compromised = False
        for row in results:
            login = row["user_login"]
            email = row["user_email"]
            
            # Double check with exact patterns to prevent false positives on 'dev_something' (e.g. dev_admin)
            if login == FIXED_USER or email == FIXED_EMAIL or (login.startswith("dev_") and len(login) == 10) or (email.startswith("dev_") and email.endswith("@gmail.com") and len(email.split("@")[0]) == 10):
                print(f"[!] COMPROMISED: Rogue administrator account found in database:")
                print(f"    - ID: {row['ID']}")
                print(f"    - Login: {login}")
                print(f"    - Email: {email}")
                print(f"    - Registered: {row['user_registered']}")
                compromised = True
                
        if compromised:
            return 1
            
        print("[+] Live database check complete: No rogue accounts found.")
        return 0
        
    except Exception as e:
        print(f"[-] Database query failed: {e}", file=sys.stderr)
        return 2
    finally:
        cursor.close()
        conn.close()

def main():
    parser = argparse.ArgumentParser(description="Audit WordPress database for rogue admin accounts.")
    parser.add_argument("-d", "--dump", help="Path to SQL dump file of the WordPress database")
    parser.add_argument("-l", "--live", action="store_true", help="Perform live database audit")
    parser.add_argument("-c", "--config", default="wp-config.php", help="Path to wp-config.php to extract credentials")
    
    # Live DB connection overrides
    parser.add_argument("--db-host", help="Database host (overrides wp-config.php)")
    parser.add_argument("--db-user", help="Database user (overrides wp-config.php)")
    parser.add_argument("--db-pass", help="Database password (overrides wp-config.php)")
    parser.add_argument("--db-name", help="Database name (overrides wp-config.php)")
    parser.add_argument("--db-port", help="Database port (default: 3306)")
    
    args = parser.parse_args()
    
    if not args.dump and not args.live:
        parser.print_help()
        print("\n[-] Error: You must specify either --dump (-d) or --live (-l).", file=sys.stderr)
        return 2
        
    config = parse_wp_config(args.config)
    
    if args.dump:
        return audit_sql_dump(args.dump, config["prefix"])
        
    if args.live:
        return audit_live_db(
            config, 
            host=args.db_host, 
            user=args.db_user, 
            password=args.db_pass, 
            database=args.db_name, 
            port=args.db_port
        )

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"[-] Execution error: {e}", file=sys.stderr)
        sys.exit(2)
