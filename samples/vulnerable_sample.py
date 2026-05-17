#!/usr/bin/env python3
# Sample vulnerable code for testing the analyzer

import os
import subprocess
import pickle
from flask import Flask, request

app = Flask(__name__)

# Vulnerability 1: Hardcoded credentials
database_password = "MySecurePassword123"
api_key = "sk-1234567890abcdef"
secret_key = "supersecretkey123"

# Vulnerability 2: SQL Injection
def get_user(user_id):
    # BAD: String concatenation in SQL
    query = "SELECT * FROM users WHERE id = " + user_id
    # db.execute(query)
    return query

# Vulnerability 3: Command Injection
def process_file(filename):
    # BAD: Shell command with user input
    cmd = "cat " + filename
    os.system(cmd)

# Vulnerability 4: XSS vulnerability
@app.route('/hello')
def hello():
    user_input = request.args.get('name')
    # BAD: User input directly into HTML
    return f"Hello {user_input}"

# Vulnerability 5: Insecure deserialization
def load_data(data):
    # BAD: Using pickle with untrusted data
    return pickle.loads(data)

# Vulnerability 6: Weak crypto
import hashlib

def hash_password(password):
    # BAD: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

# Vulnerability 7: eval() usage
def calculate(expression):
    # BAD: eval() can execute arbitrary code
    return eval(expression)

# Vulnerability 8: subprocess with shell=True
def run_command(cmd):
    # BAD: Using shell=True is dangerous
    subprocess.call(cmd, shell=True)

DEBUG = True
