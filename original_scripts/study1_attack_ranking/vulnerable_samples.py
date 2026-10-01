"""
EXPANDED VULNERABLE CODE SAMPLES (30 samples)
Doubles the original benchmark from 15 to 30 samples for stronger
statistical power. Covers the original 10 CWE categories plus more
examples per category and several new categories.

Every sample contains a genuine, documented vulnerability.
Ground truth: every sample IS vulnerable.
"""

VULNERABLE_SAMPLES = [
    # Original 15
    {"id":"V01","cwe":"CWE-89","name":"SQL Injection","code":'''def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()'''},
    {"id":"V02","cwe":"CWE-78","name":"OS Command Injection","code":'''import os
def ping_host(hostname):
    os.system("ping -c 1 " + hostname)'''},
    {"id":"V03","cwe":"CWE-79","name":"Cross-Site Scripting","code":'''def render_comment(user_comment):
    html = "<div>" + user_comment + "</div>"
    return html'''},
    {"id":"V04","cwe":"CWE-22","name":"Path Traversal","code":'''def read_file(filename):
    with open("/var/data/" + filename) as f:
        return f.read()'''},
    {"id":"V05","cwe":"CWE-798","name":"Hardcoded Credentials","code":'''def connect_db():
    password = "admin123"
    return db.connect(user="admin", password=password)'''},
    {"id":"V06","cwe":"CWE-327","name":"Weak Cryptography (MD5)","code":'''import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()'''},
    {"id":"V07","cwe":"CWE-502","name":"Insecure Deserialization","code":'''import pickle
def load_data(serialized):
    return pickle.loads(serialized)'''},
    {"id":"V08","cwe":"CWE-94","name":"Code Injection (eval)","code":'''def calculate(expression):
    return eval(expression)'''},
    {"id":"V09","cwe":"CWE-330","name":"Weak Random for Security","code":'''import random
def generate_token():
    return str(random.randint(1000, 9999))'''},
    {"id":"V10","cwe":"CWE-611","name":"XML External Entity","code":'''import xml.etree.ElementTree as ET
def parse_xml(xml_string):
    tree = ET.fromstring(xml_string)
    return tree'''},
    {"id":"V11","cwe":"CWE-89","name":"SQL Injection (format string)","code":'''def search_products(term):
    query = "SELECT * FROM products WHERE name LIKE '%%%s%%'" % term
    return cursor.execute(query)'''},
    {"id":"V12","cwe":"CWE-78","name":"Command Injection (subprocess shell)","code":'''import subprocess
def backup_file(filename):
    subprocess.call("tar -czf backup.tar.gz " + filename, shell=True)'''},
    {"id":"V13","cwe":"CWE-22","name":"Path Traversal (download)","code":'''def download(path):
    full = "downloads/" + path
    return open(full, "rb").read()'''},
    {"id":"V14","cwe":"CWE-798","name":"Hardcoded API Key","code":'''API_KEY = "sk-1234567890abcdef"
def call_api():
    return requests.get(url, headers={"Authorization": API_KEY})'''},
    {"id":"V15","cwe":"CWE-94","name":"Code Injection (exec)","code":'''def run_user_code(code_string):
    exec(code_string)'''},

    # New 15
    {"id":"V16","cwe":"CWE-89","name":"SQL Injection (f-string)","code":'''def get_order(order_id):
    query = f"SELECT * FROM orders WHERE id = {order_id}"
    return cursor.execute(query)'''},
    {"id":"V17","cwe":"CWE-78","name":"Command Injection (popen)","code":'''import os
def list_dir(path):
    return os.popen("ls " + path).read()'''},
    {"id":"V18","cwe":"CWE-79","name":"XSS (template)","code":'''def profile_page(name):
    return f"<h1>Welcome {name}</h1>"'''},
    {"id":"V19","cwe":"CWE-22","name":"Path Traversal (join)","code":'''import os
def get_template(name):
    path = os.path.join("templates", name)
    return open(path).read()'''},
    {"id":"V20","cwe":"CWE-259","name":"Hardcoded Password in Config","code":'''DB_CONFIG = {"host": "localhost", "user": "root", "password": "P@ssw0rd123"}
def get_config():
    return DB_CONFIG'''},
    {"id":"V21","cwe":"CWE-327","name":"Weak Cryptography (SHA1)","code":'''import hashlib
def sign_data(data):
    return hashlib.sha1(data.encode()).hexdigest()'''},
    {"id":"V22","cwe":"CWE-502","name":"Insecure Deserialization (yaml)","code":'''import yaml
def parse_config(text):
    return yaml.load(text, Loader=yaml.Loader)'''},
    {"id":"V23","cwe":"CWE-94","name":"Code Injection (compile)","code":'''def run_expression(expr):
    code = compile(expr, "<string>", "eval")
    return eval(code)'''},
    {"id":"V24","cwe":"CWE-330","name":"Predictable Session Token","code":'''import time
def make_session_id(user_id):
    return str(user_id) + str(int(time.time()))'''},
    {"id":"V25","cwe":"CWE-611","name":"XXE (lxml)","code":'''from lxml import etree
def load_xml(data):
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(data, parser)'''},
    {"id":"V26","cwe":"CWE-89","name":"SQL Injection (ORDER BY)","code":'''def sort_users(column):
    query = "SELECT * FROM users ORDER BY " + column
    return cursor.execute(query)'''},
    {"id":"V27","cwe":"CWE-918","name":"Server-Side Request Forgery","code":'''import requests
def fetch_url(user_url):
    return requests.get(user_url).text'''},
    {"id":"V28","cwe":"CWE-77","name":"Command Injection (eval shell)","code":'''import subprocess
def run_cmd(user_input):
    return subprocess.check_output(user_input, shell=True)'''},
    {"id":"V29","cwe":"CWE-89","name":"SQL Injection (INSERT)","code":'''def add_user(name, email):
    query = "INSERT INTO users VALUES ('" + name + "', '" + email + "')"
    return cursor.execute(query)'''},
    {"id":"V30","cwe":"CWE-295","name":"Disabled Certificate Validation","code":'''import requests
def secure_fetch(url):
    return requests.get(url, verify=False)'''},
]

if __name__ == "__main__":
    print(f"Expanded dataset: {len(VULNERABLE_SAMPLES)} samples")
    cwes = sorted(set(s['cwe'] for s in VULNERABLE_SAMPLES))
    print(f"CWE categories: {len(cwes)}")
    print(", ".join(cwes))
