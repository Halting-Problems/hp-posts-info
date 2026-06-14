import os
import sys
import subprocess
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
HUNT_FILESYSTEM_PY = SCRIPTS_DIR / "hunt_backdoor_filesystem.py"
AUDIT_DB_PY = SCRIPTS_DIR / "audit_wordpress_db.py"

def test_hunt_filesystem_clean(tmp_path):
    # Create clean directory structure
    wp_plugins = tmp_path / "wp-content" / "plugins"
    wp_plugins.mkdir(parents=True)
    
    # Create clean plugin
    normal_plugin = wp_plugins / "akismet"
    normal_plugin.mkdir()
    normal_php = normal_plugin / "akismet.php"
    normal_php.write_text("<?php\n// Just a clean plugin\n")
    
    res = subprocess.run([sys.executable, str(HUNT_FILESYSTEM_PY), str(tmp_path)], capture_output=True)
    assert res.returncode == 0

def test_hunt_filesystem_dirty_directory(tmp_path):
    wp_plugins = tmp_path / "wp-content" / "plugins"
    wp_plugins.mkdir(parents=True)
    
    # Create malicious directory disguise
    malicious_dir = wp_plugins / "database-optimizer"
    malicious_dir.mkdir()
    malicious_php = malicious_dir / "database-optimizer.php"
    malicious_php.write_text("<?php\n// Hidden backdoor\n")
    
    res = subprocess.run([sys.executable, str(HUNT_FILESYSTEM_PY), str(tmp_path)], capture_output=True)
    assert res.returncode == 1

def test_hunt_filesystem_dirty_content(tmp_path):
    wp_plugins = tmp_path / "wp-content" / "plugins"
    wp_plugins.mkdir(parents=True)
    
    # Create normal-named plugin containing the malicious XOR key
    innocent_dir = wp_plugins / "my-plugin"
    innocent_dir.mkdir()
    innocent_php = innocent_dir / "my-plugin.php"
    innocent_php.write_text("<?php\n$key = 'jX9kM2nP4qR6sT8v';\n")
    
    res = subprocess.run([sys.executable, str(HUNT_FILESYSTEM_PY), str(tmp_path)], capture_output=True)
    assert res.returncode == 1

def test_audit_db_config_parsing(tmp_path):
    # Create a mock wp-config.php
    config_file = tmp_path / "wp-config.php"
    config_file.write_text("""
    define( 'DB_NAME', 'my_wp_db' );
    define( 'DB_USER', 'wp_db_user' );
    define( 'DB_PASSWORD', 'super_secure_pass' );
    define( 'DB_HOST', 'mysql.internal:3307' );
    $table_prefix = 'wp_custom_';
    """)
    
    # Import config parser from script and test it
    sys.path.insert(0, str(SCRIPTS_DIR))
    from audit_wordpress_db import parse_wp_config
    
    config = parse_wp_config(str(config_file))
    assert config["DB_NAME"] == "my_wp_db"
    assert config["DB_USER"] == "wp_db_user"
    assert config["DB_PASSWORD"] == "super_secure_pass"
    assert config["DB_HOST"] == "mysql.internal:3307"
    assert config["prefix"] == "wp_custom_"

def test_audit_db_dump_clean(tmp_path):
    dump_file = tmp_path / "clean_dump.sql"
    dump_file.write_text("""
    -- Mock WordPress SQL Dump
    INSERT INTO `wp_users` VALUES (1,'admin','$P$B9z1c2d3e4f5g6h7i8j9k0l1m2n3o4p5','admin','admin@example.com','','2026-01-01 00:00:00','',0,'Admin');
    INSERT INTO `wp_users` VALUES (2,'john','...','john','john@example.com','','2026-02-01 00:00:00','',0,'John');
    """)
    
    res = subprocess.run([sys.executable, str(AUDIT_DB_PY), "--dump", str(dump_file)], capture_output=True)
    assert res.returncode == 0

def test_audit_db_dump_dirty_fixed(tmp_path):
    dump_file = tmp_path / "dirty_dump.sql"
    dump_file.write_text("""
    -- Mock WordPress SQL Dump
    INSERT INTO `wp_users` VALUES (1,'admin','...','admin','admin@example.com','','2026-01-01 00:00:00','',0,'Admin');
    INSERT INTO `wp_users` VALUES (3,'developer_api1','$P$B9z1c2d3e4f5g6h7i8j9','developer_api1','customer1usx@gmail.com','','2026-06-12 22:17:00','',0,'Developer');
    """)
    
    res = subprocess.run([sys.executable, str(AUDIT_DB_PY), "--dump", str(dump_file)], capture_output=True)
    assert res.returncode == 1

def test_audit_db_dump_dirty_random(tmp_path):
    dump_file = tmp_path / "dirty_dump.sql"
    dump_file.write_text("""
    -- Mock WordPress SQL Dump
    INSERT INTO `wp_users` VALUES (1,'admin','...','admin','admin@example.com','','2026-01-01 00:00:00','',0,'Admin');
    INSERT INTO `wp_users` VALUES (12,'dev_ab12cd','$P$B9z1c2d3e4f5g6h7i8j9','dev_ab12cd','dev_ab12cd@gmail.com','','2026-06-12 22:30:00','',0,'Dev Account');
    """)
    
    res = subprocess.run([sys.executable, str(AUDIT_DB_PY), "--dump", str(dump_file)], capture_output=True)
    assert res.returncode == 1
