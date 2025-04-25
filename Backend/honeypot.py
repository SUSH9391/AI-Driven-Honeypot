import os
import json
import time
from flask import Flask, request, render_template, redirect, jsonify
from dotenv import load_dotenv
import requests
from honeypot_system_hf_merged import HoneypotDiscriminator, HoneypotHFGenerator

load_dotenv()

app = Flask(__name__)

# Initialize discriminator and generator with HF API key from env
HF_API_KEY = os.getenv("HF_API_KEY")
discriminator = HoneypotDiscriminator(threshold=0.8)
generator = HoneypotHFGenerator(api_key=HF_API_KEY)

LOG_FILE = "attack_logs.json"

def log_attack(event_type, ip, user_agent, details):
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        "event_type": event_type,
        "ip": ip,
        "user_agent": user_agent,
        "details": details
    }
    # Append log entry as JSON line
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

def call_hf_behavior_detection(text):
    # Use Hugging Face zero-shot classification API for behavior anomaly detection
    api_url = "https://api-inference.huggingface.co/models/facebook/bart-large-mnli"
    headers = {"Authorization": f"Bearer {HF_API_KEY}"}
    payload = {
        "inputs": text,
        "parameters": {"candidate_labels": ["human", "bot"]}
    }
    response = requests.post(api_url, headers=headers, json=payload)
    if response.status_code == 200:
        result = response.json()
        if "labels" in result and "scores" in result:
            return result["labels"][0], result["scores"][0]
    return "unknown", 0.0

fake_users = []

@app.route('/')
def home():
    # Redirect to login page as landing page
    return redirect('/login')

# Renamed signup function to avoid duplicate endpoint error
@app.route('/signup', methods=['GET', 'POST'])
def signup_route():
    if request.method == 'POST':
        ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        username = request.form.get('username', '')
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        honeypot_field = request.form.get('honeypot_field', '')

        if honeypot_field:
            log_attack("bot_detected_honeypot_field_signup", ip, user_agent, {"username": username, "email": email})
            return redirect('/')

        behavior_text = f"Sign-up attempt by {username} with email {email}"
        behavior, score = call_hf_behavior_detection(behavior_text)

        log_attack("signup_attempt", ip, user_agent, {
            "username": username,
            "email": email,
            "password": password,
            "behavior": behavior,
            "score": score
        })

        # Add fake user to in-memory store
        fake_users.append({
            "username": username,
            "email": email,
            "password": password,
            "ip": ip,
            "user_agent": user_agent,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        })

        session_id = request.cookies.get('session_id', ip)
        analysis = discriminator.analyze_user_input(behavior_text, session_id, {"ip": ip, "user_agent": user_agent})
        if analysis["redirect_to_honeypot"]:
            return render_template("signup.html", message="Sign-up failed. Please try again.")

        return redirect('/login')

    return render_template('signup.html', message=None)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        honeypot_field = request.form.get('honeypot_field', '')

        # Detect bot if honeypot field filled
        if honeypot_field:
            log_attack("bot_detected_honeypot_field", ip, user_agent, {"username": username})
            return redirect('/')

        behavior_text = f"Login attempt by {username} with password pattern {password}"
        behavior, score = call_hf_behavior_detection(behavior_text)

        log_attack("login_attempt", ip, user_agent, {
            "username": username,
            "password": password,
            "behavior": behavior,
            "score": score
        })

        # Additional detection with discriminator
        session_id = request.cookies.get('session_id', ip)
        analysis = discriminator.analyze_user_input(behavior_text, session_id, {"ip": ip, "user_agent": user_agent})
        if analysis["redirect_to_honeypot"]:
            # Redirect or show fake login failure page
            return render_template("login.html", message="Login failed. Please try again.")

        return redirect('/product')

    return render_template('login.html', message=None)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        username = request.form.get('username', '')
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        honeypot_field = request.form.get('honeypot_field', '')

        if honeypot_field:
            log_attack("bot_detected_honeypot_field_signup", ip, user_agent, {"username": username, "email": email})
            return redirect('/')

        behavior_text = f"Sign-up attempt by {username} with email {email}"
        behavior, score = call_hf_behavior_detection(behavior_text)

        log_attack("signup_attempt", ip, user_agent, {
            "username": username,
            "email": email,
            "password": password,
            "behavior": behavior,
            "score": score
        })

        session_id = request.cookies.get('session_id', ip)
        analysis = discriminator.analyze_user_input(behavior_text, session_id, {"ip": ip, "user_agent": user_agent})
        if analysis["redirect_to_honeypot"]:
            return render_template("signup.html", message="Sign-up failed. Please try again.")

        return redirect('/login')

    return render_template('signup.html', message=None)

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        card_number = request.form.get('card_number', '')
        exp = request.form.get('exp', '')
        cvv = request.form.get('cvv', '')
        honeypot_field = request.form.get('honeypot_field', '')

        if honeypot_field:
            log_attack("bot_detected_honeypot_field_checkout", ip, user_agent, {"card_number": card_number})
            return "Processing..."

        card_info = {
            "card_number": card_number,
            "exp": exp,
            "cvv": cvv
        }
        log_attack("carding_attempt", ip, user_agent, card_info)
        return "Processing..."

    return render_template('checkout.html')

@app.route('/product')
def product():
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    honeypot_field = request.args.get('honeypot_field', '')

    # Detect scraper by missing Referer or honeypot field filled
    if not request.headers.get('Referer') or honeypot_field:
        log_attack("scraper_detected", ip, user_agent, {"note": "Missing Referer or honeypot field filled"})

    # Serve dynamic fake product listings
    fake_products = generator.generate_fake_data("SELECT * FROM products", "fake_product_listing", record_count=5)
    return render_template('product.html', products=fake_products)

@app.route('/fake-data')
def fake_data():
    # Generate fake data for attacker queries
    query = request.args.get('query', 'A fake e-commerce order:')
    fake_response = generator.generate_fake_response(query, attack_type="fake_data_generation", record_count=10)
    return jsonify(fake_response)

@app.route('/dashboard')
def dashboard():
    # Real-time attack logging dashboard
    logs = []
    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                logs.append(json.loads(line))
    except FileNotFoundError:
        logs = []

    # Sort logs by timestamp descending
    logs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    # Generate fake products for dashboard display
    fake_products = generator.generate_fake_data("SELECT * FROM products", "fake_product_listing", record_count=5)

    return render_template('dashboard.html', logs=logs, products=fake_products)

if __name__ == "__main__":
    app.run(debug=True)
