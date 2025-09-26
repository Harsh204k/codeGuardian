# Test Dataset for CodeGuardian
# Contains multiple vulnerabilities for evaluation

from flask import Flask, request
import sqlite3
import os
import subprocess
import pickle

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def vulnerable_login():
    username = request.form['username']
    password = request.form['password']
    
    # VULNERABILITY 1: SQL Injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    conn = sqlite3.connect('users.db')
    result = conn.execute(query).fetchall()
    
    return str(result)

@app.route('/file')  
def vulnerable_file_access():
    filename = request.args.get('file')
    
    # VULNERABILITY 2: Path Traversal
    file_path = os.path.join('/uploads', filename)
    with open(file_path, 'r') as f:
        content = f.read()
    
    return content

@app.route('/search')
def vulnerable_search():
    query = request.args.get('q')
    
    # VULNERABILITY 3: XSS
    return f"<h1>Search results for: {query}</h1>"

@app.route('/exec')
def vulnerable_command():
    cmd = request.args.get('cmd') 
    
    # VULNERABILITY 4: Command Injection
    result = subprocess.run(f"ping {cmd}", shell=True, capture_output=True)
    return result.stdout

@app.route('/deserialize')
def vulnerable_pickle():
    data = request.args.get('data')
    
    # VULNERABILITY 5: Insecure Deserialization
    obj = pickle.loads(data)
    return str(obj)

# VULNERABILITY 6: Hardcoded Credentials
DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

# VULNERABILITY 7: Weak Cryptography
def weak_hash(password):
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()

if __name__ == '__main__':
    # VULNERABILITY 8: Debug Mode in Production
    app.run(debug=True, host='0.0.0.0')
