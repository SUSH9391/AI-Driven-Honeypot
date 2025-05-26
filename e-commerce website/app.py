from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify
import random
import string
import time

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Needed for session management

# In-memory store for OTPs: {email: (otp, expiry_timestamp)}
otp_store = {}

@app.route('/')
def home():
    username = session.get('username')
    return render_template('home.html', username=username)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    return render_template('product.html', product_id=product_id)

@app.route('/cart')
def cart():
    if 'username' not in session:
        return redirect(url_for('login'))
    cart = session.get('cart', [])
    # For demo, product details are hardcoded; in real app, fetch from DB
    products = {
        1: {'name': 'Product 1', 'price': 999},
        2: {'name': 'Product 2', 'price': 1499},
        3: {'name': 'Product 3', 'price': 799},
    }
    cart_items = []
    total = 0
    for item in cart:
        product = products.get(item['product_id'])
        if product:
            quantity = item.get('quantity', 1)
            subtotal = product['price'] * quantity
            total += subtotal
            cart_items.append({
                'name': product['name'],
                'price': product['price'],
                'quantity': quantity,
                'subtotal': subtotal
            })
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    cart = session.get('cart', [])
    # Check if product already in cart
    for item in cart:
        if item['product_id'] == product_id:
            item['quantity'] += 1
            break
    else:
        cart.append({'product_id': product_id, 'quantity': 1})
    session['cart'] = cart
    print(f"User {session['username']} added product {product_id} to cart")
    return redirect(url_for('cart'))

@app.route('/checkout')
def checkout():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('checkout.html')

@app.route('/process_payment', methods=['POST'])
def process_payment():
    if 'username' not in session:
        return redirect(url_for('login'))
    card_number = request.form.get('card_number')
    card_expiry = request.form.get('card_expiry')
    card_cvv = request.form.get('card_cvv')
    print(f"Processing payment for user {session['username']}: Card {card_number}, Expiry {card_expiry}")
    flash('Payment successful!')
    return redirect(url_for('home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('account'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        print(f"Login attempt for user: {username}")

        if username and password:
            session['username'] = username
            session['role'] = 'customer'
            flash(f'Welcome, {username}!')
            return redirect(url_for('account'))
        else:
            flash('Login failed. Please try again.')

    return render_template('login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if 'username' in session and session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        role = request.form.get('role')
        adminid = request.form.get('adminid')
        password = request.form.get('password')
        print(f"Admin login attempt: Role={role}, AdminID={adminid}")

        # For demo, hardcoded admin credentials; replace with DB lookup
        valid_admins = {
            'owner': {'adminid': 'AD1001', 'password': '12345'},
            'manager': {'adminid': 'manager1', 'password': 'managerpass'},
            'staff': {'adminid': 'staff1', 'password': 'staffpass'}
        }

        admin = valid_admins.get(role)
        if admin and admin['adminid'] == adminid and admin['password'] == password:
            session['username'] = adminid
            session['role'] = 'admin'
            flash(f'Welcome, {role} {adminid}!')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Admin login failed. Please try again.')

    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin_login'))
    username = session.get('username')
    role = session.get('role')
    return f"Welcome to the Admin Dashboard, {role} {username}!"

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        first_name = request.form.get('first-name')
        last_name = request.form.get('last-name')
        email = request.form.get('email')
        password = request.form.get('password')

        print(f"New signup: Username={username}, Name={first_name} {last_name}, Email={email}")

        # Here you would usually save to a database

        flash('Signup successful! Please login now.')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/send_otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'success': False, 'message': 'Email is required'}), 400

    otp = ''.join(random.choices(string.digits, k=6))
    expiry = time.time() + 120
    otp_store[email] = (otp, expiry)

    print(f"Sending OTP to {email}: {otp}")  # In real app, you'd send via email

    return jsonify({'success': True})

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({'verified': False, 'message': 'Email and OTP are required'}), 400

    stored_otp, expiry = otp_store.get(email, (None, 0))
    if stored_otp == otp and time.time() <= expiry:
        otp_store.pop(email, None)
        return jsonify({'verified': True})
    else:
        return jsonify({'verified': False})

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('home'))

@app.route('/account')
def account():
    if 'username' not in session:
        return redirect(url_for('login'))
    # Dummy user data and orders
    user = {
        'username': session['username'],
        'email': f'{session["username"]}@example.com'
    }
    orders = [
        {'id': 1, 'date': '2025-04-20', 'total': 2999, 'status': 'Delivered'},
        {'id': 2, 'date': '2025-04-25', 'total': 1599, 'status': 'Processing'}
    ]
    username = session.get('username')
    return render_template('account.html', user=user, orders=orders, username=username)

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = request.form.get('username')
    email = request.form.get('email')
    # Here you would update user profile in database
    flash('Profile updated successfully!')
    return redirect(url_for('account'))

if __name__ == '__main__':
    app.run(debug=True)
