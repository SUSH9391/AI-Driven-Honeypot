import os
import re
import json
import time
import uuid
import logging
import random
import datetime
import argparse
from typing import Dict, List, Any, Optional, Tuple, Union
from flask import Flask, request, jsonify, render_template_string
import requests
from dotenv import load_dotenv

# ========================
# Logging Configuration
# ========================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("honeypot_system_hf.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("HoneypotSystem")

# ========================
# Honeypot Discriminator Class (from honeypot_discriminator.py)
# ========================
class HoneypotDiscriminator:
    """
    Rule-based discriminator for honeypot systems that detects malicious users
    and attack attempts using pattern matching and heuristics.
    This discriminator analyzes user behavior, queries, and interaction patterns
    to determine if a user is legitimate or an attacker.
    """
    def __init__(self, api_key: Optional[str] = None, threshold: float = 0.7):
        self.threshold = threshold
        self._initialize_detection_patterns()
        self.user_history = {}

    def _initialize_detection_patterns(self):
        self.sql_injection_patterns = [
            r"'(\s*)(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP)(\s+)",
            r"(\s+)--(\s|$)",
            r"\/\*.*\*\/",
            r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP)",
            r"'(\s*)(\)|;|--)",
            r"(\b|')(\s*)(WAITFOR|DELAY|BENCHMARK|SLEEP)(\s*)\(",
            r"(\b|')(\s*)(LOAD_FILE|OUTFILE|DUMPFILE)(\s*)\("
        ]
        self.legitimate_sql_patterns = [
            r"^SELECT\s+\*\s+FROM\s+\w+$",
            r"^SELECT\s+[\w\s,]+\s+FROM\s+\w+$",
            r"^SELECT\s+[\w\s,]+\s+FROM\s+\w+\s+WHERE\s+\w+\s*=\s*\d+$",
            r"^SELECT\s+[\w\s,]+\s+FROM\s+\w+\s+WHERE\s+\w+\s*=\s*'\w+'$",
            r"^SELECT\s+[\w\s,]+\s+FROM\s+\w+\s+ORDER\s+BY\s+\w+(\s+(ASC|DESC))?$",
            r"^SELECT\s+[\w\s,]+\s+FROM\s+\w+\s+LIMIT\s+\d+$",
            r"^SELECT\s+[\w\s,]+\s+FROM\s+\w+\s+JOIN\s+\w+\s+ON\s+\w+\.\w+\s*=\s*\w+\.\w+$"
        ]
        self.xss_patterns = [
            r"<script.*?>",
            r"javascript:",
            r"onerror=",
            r"onload=",
            r"eval\(",
            r"document\.cookie",
            r"alert\(",
            r"String\.fromCharCode\(",
            r"<img.*?src=.*?onerror=.*?>",
            r"<iframe.*?src=.*?>"
        ]
        self.command_injection_patterns = [
            r"(\||&|;|\$\(|\`)",
            r"(\b|;)(\s*)(cat|ls|dir|pwd|whoami|cd|rm|cp|mv|chmod|chown|wget|curl)(\s+).*(\||&|;|\$\(|\`)",
            r"\/etc\/passwd",
            r"\/bin\/bash",
            r"C:\\Windows\\System32"
        ]
        self.path_traversal_patterns = [
            r"\.\.\/",
            r"\.\.\\",
            r"\/etc\/",
            r"C:\\Windows",
            r"file:\/\/",
            r"\/var\/www",
            r"\/home\/",
            r"\/root\/"
        ]

    def _check_pattern_match(self, input_str: str, patterns: List[str]) -> bool:
        for pattern in patterns:
            if re.search(pattern, input_str, re.IGNORECASE):
                return True
        return False

    def _is_legitimate_sql(self, query: str) -> bool:
        normalized_query = ' '.join(query.split())
        for pattern in self.legitimate_sql_patterns:
            if re.match(pattern, normalized_query, re.IGNORECASE):
                return True
        if re.match(r"^SELECT\s+.+\s+FROM\s+\w+(\s+WHERE\s+\w+\s*(=|<|>)\s*('[^']*'|\d+))?$", normalized_query, re.IGNORECASE):
            return True
        return False

    def _rule_based_detection(self, user_input: str) -> Tuple[bool, float, str]:
        if user_input.strip().upper().startswith("SELECT"):
            if self._is_legitimate_sql(user_input):
                return False, 0.0, "None"
        if self._check_pattern_match(user_input, self.sql_injection_patterns):
            if "'" in user_input and ("OR" in user_input.upper() or "AND" in user_input.upper() or "--" in user_input):
                return True, 0.9, "SQL Injection"
            elif "UNION" in user_input.upper() and "SELECT" in user_input.upper():
                return True, 0.95, "SQL Injection"
            elif ";" in user_input and any(keyword in user_input.upper() for keyword in ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP"]):
                return True, 0.9, "SQL Injection"
            else:
                return True, 0.7, "Potential SQL Injection"
        if self._check_pattern_match(user_input, self.xss_patterns):
            return True, 0.9, "Cross-Site Scripting (XSS)"
        if self._check_pattern_match(user_input, self.command_injection_patterns):
            return True, 0.9, "Command Injection"
        if self._check_pattern_match(user_input, self.path_traversal_patterns):
            return True, 0.85, "Path Traversal"
        return False, 0.0, "None"

    def _advanced_detection(self, user_input: str, user_id: str, context: Optional[Dict[str, Any]] = None) -> Tuple[bool, float, str]:
        user_history = self.user_history.get(user_id, [])
        malicious_attempts = sum(1 for interaction in user_history if interaction.get("is_malicious", False))
        if malicious_attempts >= 3:
            return True, 0.85, "Repeated Attack Attempts"
        if user_input.strip().upper().startswith("SELECT"):
            if self._is_legitimate_sql(user_input):
                return False, 0.0, "None"
        sql_injection_indicators = [
            "union select", "information_schema.tables", "information_schema.columns",
            "sysobjects", "version()", "database()", "sleep(", "benchmark(",
            "order by 1--", "group by 1--", "' or '1'='1", "' or 1=1--", "admin'--"
        ]
        sql_indicator_count = sum(1 for pattern in sql_injection_indicators if pattern in user_input.lower())
        if sql_indicator_count >= 1:
            confidence = min(0.7 + (sql_indicator_count * 0.1), 0.95)
            return True, confidence, "Advanced SQL Injection"
        xss_indicators = [
            "<svg onload=", "<img src=x onerror=", "javascript:alert",
            "document.cookie", "document.location", "window.location", "eval(", "fromcharcode"
        ]
        xss_indicator_count = sum(1 for pattern in xss_indicators if pattern in user_input.lower())
        if xss_indicator_count >= 1:
            confidence = min(0.8 + (xss_indicator_count * 0.05), 0.95)
            return True, confidence, "Advanced XSS"
        nosql_indicators = ["$where:", "$regex:", "$ne:", "$gt:", "$lt:", "{"]
        nosql_indicator_count = sum(1 for pattern in nosql_indicators if pattern in user_input)
        if nosql_indicator_count >= 2:
            return True, 0.9, "NoSQL Injection"
        ldap_indicators = ["cn=", "ou=", "dc=", ")(|", ")(!", "*)("]
        ldap_indicator_count = sum(1 for pattern in ldap_indicators if pattern in user_input)
        if ldap_indicator_count >= 2:
            return True, 0.9, "LDAP Injection"
        template_indicators = ["{{", "${", "<%= ", "<%", "#if", "#set"]
        if any(pattern in user_input for pattern in template_indicators) and any(code in user_input.lower() for code in ["system", "exec", "eval", "process", "require", "import"]):
            return True, 0.85, "Template Injection"
        if re.search(r"https?://(?!trusted-domain\.com)[^\s]+", user_input) and any(term in user_input.lower() for term in ["download", "exec", "install", "run", "script"]):
            return True, 0.7, "Suspicious URL"
        if re.search(r"[A-Za-z0-9+/]{40,}={0,2}", user_input):
            return True, 0.75, "Encoded Payload"
        special_char_count = sum(1 for char in user_input if char in "!@#$%^&*()+={}[]|\\:;\"'<>,.?/~`")
        if special_char_count > len(user_input) * 0.4 and len(user_input) > 15:
            return True, 0.65, "Suspicious Character Pattern"
        return False, 0.0, "None"

    def analyze_user_input(self, user_input: str, user_id: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not user_input or len(user_input.strip()) < 3:
            return {
                "is_malicious": False,
                "confidence": 0.0,
                "attack_type": "None",
                "detection_method": "basic",
                "timestamp": time.time(),
                "redirect_to_honeypot": False
            }
        if user_input.strip().upper().startswith("SELECT"):
            if self._is_legitimate_sql(user_input):
                result = {
                    "is_malicious": False,
                    "confidence": 0.0,
                    "attack_type": "None",
                    "detection_method": "whitelist",
                    "timestamp": time.time(),
                    "redirect_to_honeypot": False
                }
                if user_id not in self.user_history:
                    self.user_history[user_id] = []
                self.user_history[user_id].append({
                    "timestamp": time.time(),
                    "input": user_input,
                    "is_malicious": False,
                    "confidence": 0.0,
                    "attack_type": "None"
                })
                logger.info(f"User {user_id}: LEGITIMATE (whitelisted SQL query)")
                return result
        is_malicious, confidence, attack_type = self._rule_based_detection(user_input)
        detection_method = "rule-based"
        if not is_malicious or confidence < 0.8:
            adv_is_malicious, adv_confidence, adv_attack_type = self._advanced_detection(
                user_input, user_id, context
            )
            if adv_confidence > confidence:
                is_malicious = adv_is_malicious
                confidence = adv_confidence
                attack_type = adv_attack_type
                detection_method = "advanced"
        if user_id not in self.user_history:
            self.user_history[user_id] = []
        self.user_history[user_id].append({
            "timestamp": time.time(),
            "input": user_input,
            "is_malicious": is_malicious,
            "confidence": confidence,
            "attack_type": attack_type
        })
        if len(self.user_history[user_id]) > 20:
            self.user_history[user_id] = self.user_history[user_id][-20:]
        if "SQL Injection" in attack_type and "'" in user_input and ("OR" in user_input.upper() or "AND" in user_input.upper() or "--" in user_input):
            is_malicious = True
            confidence = max(confidence, 0.9)
            attack_type = "SQL Injection"
            detection_method = "rule-based"
        redirect_to_honeypot = is_malicious and confidence >= self.threshold
        if is_malicious and confidence < 0.75:
            if user_input.strip().upper().startswith("SELECT") and not any(char in user_input for char in ["'", "\"", ";", "--", "/*", "*/"]):
                is_malicious = False
                confidence = 0.0
                attack_type = "None"
                redirect_to_honeypot = False
        result = {
            "is_malicious": is_malicious,
            "confidence": confidence,
            "attack_type": attack_type if is_malicious else "None",
            "detection_method": detection_method,
            "timestamp": time.time(),
            "redirect_to_honeypot": redirect_to_honeypot
        }
        logger.info(f"User {user_id}: {'MALICIOUS' if is_malicious else 'LEGITIMATE'} " +
                   f"(confidence: {confidence:.2f}, attack: {attack_type})")
        return result

# ========================
# Honeypot HF Generator (from honeypot_hf_generator.py)
# ========================
class HoneypotHFGenerator:
    """
    Honeypot data generator that creates realistic fake data
    for cybersecurity honeypot systems using Hugging Face's API.
    """
    def __init__(self, api_key: Optional[str] = None, model_name: str = "gpt2"):
        load_dotenv()
        self.api_key = api_key or os.getenv("HF_API_KEY")
        if not self.api_key:
            raise ValueError("Hugging Face API key is required. Provide it as an argument or set HF_API_KEY environment variable.")
        self.model_name = model_name
        self.api_url = f"https://api-inference.huggingface.co/models/{model_name}"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        self.generation_history = []
        self._initialize_data_generators()

    def _initialize_data_generators(self):
        self.first_names = [
            "James", "John", "Robert", "Michael", "William", "David", "Richard", "Joseph", "Thomas", "Charles",
            "Mary", "Patricia", "Jennifer", "Linda", "Elizabeth", "Barbara", "Susan", "Jessica", "Sarah", "Karen"
        ]
        self.last_names = [
            "Smith", "Johnson", "Williams", "Jones", "Brown", "Davis", "Miller", "Wilson", "Moore", "Taylor",
            "Anderson", "Thomas", "Jackson", "White", "Harris", "Martin", "Thompson", "Garcia", "Martinez", "Robinson"
        ]
        self.email_domains = [
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
            "mail.com", "protonmail.com", "icloud.com", "example.com", "company.com"
        ]
        self.street_names = [
            "Main St", "Oak St", "Maple Ave", "Washington St", "Park Ave",
            "Elm St", "Lake St", "Pine St", "Cedar Ave", "Hill St"
        ]
        self.cities = [
            "New York", "Los Angeles", "Chicago", "Houston", "Phoenix",
            "Philadelphia", "San Antonio", "San Diego", "Dallas", "San Jose"
        ]
        self.states = [
            "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA",
            "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD"
        ]
        self.company_names = [
            "Acme Corporation", "Globex", "Soylent Corp", "Initech", "Umbrella Corporation",
            "Stark Industries", "Wayne Enterprises", "Cyberdyne Systems", "Oscorp", "LexCorp"
        ]
        self.product_names = [
            "Premium Laptop", "Smartphone Pro", "Wireless Headphones", "Smart Watch", "4K Monitor",
            "Gaming Console", "Bluetooth Speaker", "Tablet Air", "Fitness Tracker", "Wireless Earbuds"
        ]
        self.status_options = [
            "Active", "Inactive", "Pending", "Suspended", "Archived",
            "Completed", "Processing", "Shipped", "Delivered", "Cancelled"
        ]
        self.user_roles = [
            "Admin", "User", "Manager", "Editor", "Viewer",
            "Moderator", "Guest", "Developer", "Analyst", "Support"
        ]

    def _extract_data_schema_from_query(self, query: str) -> Dict[str, str]:
        return self._enhanced_schema_extraction(query)

    def _enhanced_schema_extraction(self, query: str) -> Dict[str, str]:
        schema = {}
        query_lower = query.lower()
        if "select " in query_lower and " from " in query_lower:
            select_part = query_lower.split("select ")[1].split(" from ")[0]
            select_part = select_part.replace("count(", "count_").replace("sum(", "sum_")
            select_part = select_part.replace("avg(", "avg_").replace("max(", "max_")
            select_part = select_part.replace("min(", "min_").replace(")", "")
            fields = [f.strip() for f in select_part.split(",")]
            for field in fields:
                if " as " in field:
                    field = field.split(" as ")[1]
                clean = field.replace("'", "").replace('"', '').replace("`", "")
                if clean.startswith("*"):
                    continue
                if any(word in clean for word in ["id", "count_", "sum_", "avg_", "min_", "max_"]):
                    schema[clean] = "int"
                elif any(word in clean for word in ["date", "time", "created", "updated"]):
                    schema[clean] = "datetime"
                elif any(word in clean for word in ["email"]):
                    schema[clean] = "email"
                elif any(word in clean for word in ["name", "username", "title"]):
                    schema[clean] = "str"
                elif any(word in clean for word in ["role", "status"]):
                    schema[clean] = "str"
                elif any(word in clean for word in ["price", "total", "amount"]):
                    schema[clean] = "float"
                else:
                    schema[clean] = "str"
        return schema if schema else {
            "id": "int",
            "name": "str",
            "email": "email",
            "created_at": "datetime"
        }

    def _generate_fake_field(self, field: str, data_type: str, record_num: int) -> Any:
        if data_type == "int":
            return random.randint(1000, 9999)
        elif data_type == "datetime":
            dt = datetime.datetime.now() - datetime.timedelta(days=random.randint(0, 1000))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        elif data_type == "email":
            first = random.choice(self.first_names).lower()
            last = random.choice(self.last_names).lower()
            domain = random.choice(self.email_domains)
            return f"{first}.{last}{record_num}@{domain}"
        elif data_type == "float":
            return round(random.uniform(10.0, 1500.0), 2)
        elif "name" in field:
            return f"{random.choice(self.first_names)} {random.choice(self.last_names)}"
        elif "role" in field:
            return random.choice(self.user_roles)
        elif "status" in field:
            return random.choice(self.status_options)
        elif "product" in field:
            return random.choice(self.product_names)
        elif "street" in field:
            return f"{random.randint(100, 9999)} {random.choice(self.street_names)}"
        elif "city" in field:
            return random.choice(self.cities)
        elif "company" in field:
            return random.choice(self.company_names)
        else:
            return f"Fake{field.capitalize()}{record_num}"

    def generate_fake_data(self, query: str, attack_type: str, record_count: int = 10) -> List[Dict[str, Any]]:
        schema = self._extract_data_schema_from_query(query)
        fake_data = []
        for i in range(record_count):
            row = {field: self._generate_fake_field(field, dtype, i) for field, dtype in schema.items()}
            fake_data.append(row)
        self.generation_history.append({"query": query, "attack_type": attack_type, "timestamp": time.time(), "fake_sample": fake_data[0] if fake_data else {}})
        return fake_data

    def generate_fake_response(self, input_context: str, attack_type: str = "Unknown", record_count: int = 10) -> Dict[str, Any]:
        return self.generate_fake_data(input_context, attack_type, record_count=record_count)

# ========================
# App Initialization and Routing (from honeypot_system_hf.py original logic)
# ========================
load_dotenv()
app = Flask(__name__)

generator = HoneypotHFGenerator()
discriminator = HoneypotDiscriminator(threshold=0.8)
sessions = {}

real_database = {
    "users": [
        {"id": 1, "username": "admin", "email": "admin@example.com", "role": "administrator"},
        {"id": 2, "username": "user1", "email": "user1@example.com", "role": "user"},
        {"id": 3, "username": "user2", "email": "user2@example.com", "role": "user"}
    ],
    "products": [
        {"id": 101, "name": "Laptop", "price": 999.99, "stock": 50},
        {"id": 102, "name": "Smartphone", "price": 499.99, "stock": 100},
        {"id": 103, "name": "Tablet", "price": 299.99, "stock": 75}
    ],
    "orders": [
        {"id": 1001, "user_id": 2, "product_id": 101, "quantity": 1, "total": 999.99},
        {"id": 1002, "user_id": 3, "product_id": 102, "quantity": 2, "total": 999.98}
    ]
}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>E-commerce Database Query Interface</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .container { max-width: 800px; margin: 0 auto; }
        .query-form { margin-bottom: 20px; }
        textarea { width: 100%; height: 100px; margin-bottom: 10px; }
        button { padding: 8px 16px; background-color: #4CAF50; color: white; border: none; cursor: pointer; }
        .results { border: 1px solid #ddd; padding: 15px; background-color: #f9f9f9; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .error { color: red; }
        .info { color: blue; }
    </style>
</head>
<body>
    <div class="container">
        <h1>E-commerce Database Query Interface (HF Version)</h1>
        <p>Enter SQL queries to retrieve data from the e-commerce database.</p>
        <div class="query-form">
            <form method="POST" action="/query">
                <textarea name="query" placeholder="Enter SQL query here...">{{ query }}</textarea>
                <button type="submit">Execute Query</button>
            </form>
        </div>
        {% if error %}
        <div class="error">
            <p>Error: {{ error }}</p>
        </div>
        {% endif %}
        {% if info %}
        <div class="info">
            <p>{{ info }}</p>
        </div>
        {% endif %}
        {% if results %}
        <div class="results">
            <h2>Query Results</h2>
            {% if results|length > 0 %}
                <table>
                    <thead>
                        <tr>
                            {% for key in results[0].keys() %}
                            <th>{{ key }}</th>
                            {% endfor %}
                        </tr>
                    </thead>
                    <tbody>
                        {% for row in results %}
                        <tr>
                            {% for value in row.values() %}
                            <td>{{ value }}</td>
                            {% endfor %}
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            {% else %}
                <p>No results found.</p>
            {% endif %}
        </div>
        {% endif %}
    </div>
</body>
</html>
"""

def get_session_id():
    session_id = request.cookies.get('session_id')
    if not session_id:
        session_id = str(uuid.uuid4())
    return session_id

def execute_real_query(query):
    query_lower = query.lower()
    if "select" not in query_lower:
        return [], "Only SELECT queries are supported"
    if "from users" in query_lower:
        if "where" in query_lower:
            try:
                where_part = query_lower.split("where")[1].strip()
                if "id =" in where_part or "id=" in where_part:
                    id_value = None
                    if "id = " in where_part:
                        id_part = where_part.split("id = ")[1].strip()
                    else:
                        id_part = where_part.split("id=")[1].strip()
                    if id_part.startswith("'") or id_part.startswith('"'):
                        id_value = id_part[1:].split("'")[0].split('"')[0]
                    else:
                        id_value = id_part.split()[0].split(";")[0]
                    try:
                        id_value = int(id_value)
                        filtered_users = [user for user in real_database["users"] if user["id"] == id_value]
                        return filtered_users, None
                    except ValueError:
                        pass
                return real_database["users"], None
            except Exception as e:
                return real_database["users"], None
        else:
            return real_database["users"], None
    elif "from products" in query_lower:
        if "where" in query_lower:
            try:
                where_part = query_lower.split("where")[1].strip()
                if "id =" in where_part or "id=" in where_part:
                    id_value = None
                    if "id = " in where_part:
                        id_part = where_part.split("id = ")[1].strip()
                    else:
                        id_part = where_part.split("id=")[1].strip()
                    if id_part.startswith("'") or id_part.startswith('"'):
                        id_value = id_part[1:].split("'")[0].split('"')[0]
                    else:
                        id_value = id_part.split()[0].split(";")[0]
                    try:
                        id_value = int(id_value)
                        filtered_products = [product for product in real_database["products"] if product["id"] == id_value]
                        return filtered_products, None
                    except ValueError:
                        pass
                return real_database["products"], None
            except Exception as e:
                return real_database["products"], None
        else:
            return real_database["products"], None
    elif "from orders" in query_lower:
        if "where" in query_lower:
            try:
                where_part = query_lower.split("where")[1].strip()
                if "id =" in where_part or "id=" in where_part:
                    id_value = None
                    if "id = " in where_part:
                        id_part = where_part.split("id = ")[1].strip()
                    else:
                        id_part = where_part.split("id=")[1].strip()
                    if id_part.startswith("'") or id_part.startswith('"'):
                        id_value = id_part[1:].split("'")[0].split('"')[0]
                    else:
                        id_value = id_part.split()[0].split(";")[0]
                    try:
                        id_value = int(id_value)
                        filtered_orders = [order for order in real_database["orders"] if order["id"] == id_value]
                        return filtered_orders, None
                    except ValueError:
                        pass
                return real_database["orders"], None
            except Exception as e:
                return real_database["orders"], None
        else:
            return real_database["orders"], None
    else:
        for table_name in real_database.keys():
            if table_name in query_lower:
                return real_database[table_name], None
        return [], "Unknown table or invalid query. Available tables: users, products, orders"

@app.route('/')
def index():
    session_id = get_session_id()
    response = render_template_string(HTML_TEMPLATE, query="", results=None, error=None, info=None)
    return response

@app.route('/query', methods=['POST'])
def query():
    query = request.form.get('query', '')
    session_id = get_session_id()
    client_ip = request.remote_addr
    context = {
        "ip_address": client_ip,
        "user_agent": request.headers.get('User-Agent', ''),
        "endpoint": "/query",
        "method": "POST"
    }
    analysis = discriminator.analyze_user_input(query, session_id, context)
    logger.info(f"Query: {query}")
    logger.info(f"Analysis: {json.dumps(analysis)}")
    if analysis["redirect_to_honeypot"]:
        logger.warning(f"Redirecting to honeypot: {session_id} - {analysis['attack_type']}")
        try:
            fake_data = generator.generate_fake_data(
                query=query,
                attack_type=analysis["attack_type"],
                record_count=10
            )
            return render_template_string(
                HTML_TEMPLATE,
                query=query,
                results=fake_data,
                error=None,
                info="Query executed successfully."
            )
        except Exception as e:
            logger.error(f"Error generating fake data: {e}")
            return render_template_string(
                HTML_TEMPLATE,
                query=query,
                results=None,
                error="Database error: Invalid query syntax or insufficient permissions.",
                info=None
            )
    else:
        results, error = execute_real_query(query)
        return render_template_string(
            HTML_TEMPLATE,
            query=query,
            results=results,
            error=error,
            info=None if error else "Query executed successfully."
        )

@app.route('/api/query', methods=['POST'])
def api_query():
    data = request.get_json()
    query = data.get('query', '')
    session_id = get_session_id()
    client_ip = request.remote_addr
    context = {
        "ip_address": client_ip,
        "user_agent": request.headers.get('User-Agent', ''),
        "endpoint": "/api/query",
        "method": "POST"
    }
    analysis = discriminator.analyze_user_input(query, session_id, context)
    logger.info(f"API Query: {query}")
    logger.info(f"Analysis: {json.dumps(analysis)}")
    if analysis["redirect_to_honeypot"]:
        logger.warning(f"API redirecting to honeypot: {session_id} - {analysis['attack_type']}")
        try:
            fake_data = generator.generate_fake_data(
                query=query,
                attack_type=analysis["attack_type"],
                record_count=10
            )
            return jsonify({
                "success": True,
                "results": fake_data,
                "count": len(fake_data)
            })
        except Exception as e:
            logger.error(f"Error generating fake data: {e}")
            return jsonify({
                "success": False,
                "error": "Database error: Invalid query syntax or insufficient permissions."
            }), 400
    else:
        results, error = execute_real_query(query)
        if error:
            return jsonify({
                "success": False,
                "error": error
            }), 400
        else:
            return jsonify({
                "success": True,
                "results": results,
                "count": len(results)
            })

@app.route('/stats', methods=['GET'])
def stats():
    session_count = len(sessions)
    malicious_sessions = sum(1 for session_id, data in discriminator.user_history.items() 
                            if any(interaction.get("is_malicious", False) for interaction in data))
    total_queries = sum(len(data) for session_id, data in discriminator.user_history.items())
    malicious_queries = sum(sum(1 for interaction in data if interaction.get("is_malicious", False)) 
                           for session_id, data in discriminator.user_history.items())
    attack_types = {}
    for session_id, data in discriminator.user_history.items():
        for interaction in data:
            if interaction.get("is_malicious", False) and interaction.get("attack_type") != "None":
                attack_type = interaction.get("attack_type")
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
    stats = {
        "total_sessions": session_count,
        "malicious_sessions": malicious_sessions,
        "total_queries": total_queries,
        "malicious_queries": malicious_queries,
        "attack_types": attack_types,
        "uptime_seconds": int(time.time() - start_time)
    }
    return jsonify(stats)

def main():
    global start_time
    start_time = time.time()
    parser = argparse.ArgumentParser(description="Run the honeypot system")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to run the server on")
    parser.add_argument("--port", type=int, default=5000, help="Port to run the server on")
    parser.add_argument("--debug", action="store_true", help="Run in debug mode")
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == "__main__":
    main()