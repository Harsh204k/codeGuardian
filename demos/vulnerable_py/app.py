#!/usr/bin/env python3
"""
Vulnerable Python Application Demo
Demonstrates various security vulnerabilities for testing CodeGuardian
"""

import subprocess
import pickle
import os
import sys
import random
import sqlite3
import yaml
import json

# Hardcoded credentials - major security risk
DB_PASSWORD = "admin123!"  # PY-HARDCRED-001
API_KEY = "sk-1234567890abcdef1234567890abcdef"  # PY-HARDCRED-002
SECRET_KEY = "mySuperSecretKey123456789"  # PY-HARDCRED-003

def main():
    print("=== Vulnerable Python Application Demo ===")

    # Get user input
    user_input = sys.argv[1] if len(sys.argv) > 1 else "admin"
    user_id = sys.argv[2] if len(sys.argv) > 2 else "1"
    file_name = sys.argv[3] if len(sys.argv) > 3 else "config.txt"

    # SQL Injection vulnerability
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    sql = f"SELECT * FROM users WHERE id = {user_id} AND name = '{user_input}'"  # PY-SQLI-001
    cursor.execute(sql)
    results = cursor.fetchall()
    print(f"Query results: {results}")

    # Command injection vulnerability
    cmd = f"ls -la {user_input}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)  # PY-CMDI-001
    print(f"Command output: {result.stdout}")

    # Path traversal vulnerability
    full_path = os.path.join("uploads", file_name)  # PY-PATH-001
    if os.path.exists(full_path):
        with open(full_path, 'r') as f:
            content = f.read()
        print(f"File content: {content}")

    # Insecure deserialization - pickle
    if len(sys.argv) > 4:
        data = sys.argv[4]
        try:
            obj = pickle.loads(bytes.fromhex(data))  # PY-DESER-001
            print(f"Deserialized object: {obj}")
        except:
            print("Failed to deserialize")

    # Insecure deserialization - YAML (if PyYAML is available)
    try:
        import yaml
        yaml_data = f"!!python/object:user_input {user_input}"
        obj = yaml.load(yaml_data, Loader=yaml.FullLoader)  # PY-DESER-002
        print(f"YAML object: {obj}")
    except ImportError:
        print("PyYAML not available")

    # Weak random number generation
    random.seed(12345)  # Predictable seed
    session_id = random.randint(1000, 9999)  # PY-WEAKRAND-001
    print(f"Session ID: {session_id}")

    # Buffer overflow simulation with lists
    buffer = [0] * 10
    for i in range(15):  # PY-BUFFER-001
        buffer[i] = i
    print(f"Buffer: {buffer}")

    # Eval vulnerability - extremely dangerous
    code = user_input if user_input.replace(' ', '').replace('print', '').replace('(', '').replace(')', '') else "print('Hello')"
    try:
        eval(code)  # PY-EVAL-001
    except:
        print("Eval failed")

    # Weak encryption example
    encrypted = encrypt_password(user_input)
    print(f"Encrypted password: {encrypted}")

    # Hardcoded API call simulation
    call_external_api(API_KEY)

    # File inclusion vulnerability simulation
    module_name = user_input.split('.')[0]  # Remove extension
    try:
        __import__(module_name)  # PY-FI-001 - dangerous import
        print(f"Imported module: {module_name}")
    except ImportError:
        print(f"Could not import: {module_name}")

    print("Application completed")

def load_data(data):
    """Insecure deserialization function"""
    return pickle.loads(data)  # PY-DESER-003

def encrypt_password(password):
    """Weak encryption using simple XOR"""
    encrypted = []
    for char in password:
        encrypted.append(chr(ord(char) ^ 0x55))  # PY-WEAKENC-001
    return ''.join(encrypted)

def call_external_api(api_key):
    """Simulated API call with hardcoded credentials"""
    print(f"Calling API with key: {api_key[:10]}...")

def process_user_input(input_str):
    """Process user input with potential XSS"""
    html = f"<div>Welcome {input_str}</div>"  # PY-XSS-001
    return html

if __name__ == "__main__":
    main()
