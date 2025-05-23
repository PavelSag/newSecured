import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, current_app
from werkzeug import security
import os
import re
import html
import hmac
import hashlib
import secrets
from config import PASSWORD_CONFIG, PASSWORD_ERROR_MESSAGES, LOGIN_CONFIG, FORBIDDEN_SUBSTRINGS
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from dotenv import load_dotenv



app = Flask(__name__)
app.secret_key = 'your_secret_key'  

# Print current working directory
print("Current working directory:", os.getcwd())

# Try to load .env file
env_path = os.path.join(os.getcwd(), '.env')
print("Looking for .env file at:", env_path)
print("Does .env file exist?", os.path.exists(env_path))

load_dotenv()

# Load and validate SMTP settings
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))  # Default to 587 if not specified
SMTP_USERNAME = os.getenv('SMTP_USERNAME')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')

# Debug prints
print("\nSMTP Settings:")
print(f"Server: {SMTP_SERVER}")
print(f"Port: {SMTP_PORT}")
print(f"Username: {SMTP_USERNAME}")
print(f"Password: {'*' * len(SMTP_PASSWORD) if SMTP_PASSWORD else 'Not set'}")

if not all([SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD]):
    print("\nWarning: Some SMTP settings are missing. Please check your .env file.")
    print("Make sure your .env file contains:")
    print("SMTP_SERVER=smtp.gmail.com")
    print("SMTP_PORT=587")
    print("SMTP_USERNAME=your.email@gmail.com")
    print("SMTP_PASSWORD=your_app_password")

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row  
    return conn

def init_db():
    conn = get_db_connection()
    
    conn.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.execute('''
    CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    conn.execute('''
    CREATE TABLE IF NOT EXISTS password_resets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    conn.execute('''
    CREATE TABLE IF NOT EXISTS password_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        password TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    conn.commit()
    conn.close()
    print("Database initialized successfully")

def validate_password(password):

    password_lower = password.lower()
    for substring in FORBIDDEN_SUBSTRINGS:
        if substring in password_lower:
            return False, PASSWORD_ERROR_MESSAGES['forbidden_substring']

    if len(password) < PASSWORD_CONFIG['min_length']:
        return False, PASSWORD_ERROR_MESSAGES['min_length'].format(
            min_length=PASSWORD_CONFIG['min_length']
        )
    
    requirements_met = 0
    requirements_messages = []

    has_uppercase = any(c.isupper() for c in password)
    if has_uppercase:
        requirements_met += 1
    elif PASSWORD_CONFIG['require_uppercase']:
        requirements_messages.append(PASSWORD_ERROR_MESSAGES['require_uppercase'])
    
    has_lowercase = any(c.islower() for c in password)
    if has_lowercase:
        requirements_met += 1
    elif PASSWORD_CONFIG['require_lowercase']:
        requirements_messages.append(PASSWORD_ERROR_MESSAGES['require_lowercase'])
   
    has_digit = any(c.isdigit() for c in password)
    if has_digit:
        requirements_met += 1
    elif PASSWORD_CONFIG['require_digit']:
        requirements_messages.append(PASSWORD_ERROR_MESSAGES['require_digit'])
    
    special_chars = PASSWORD_CONFIG['special_chars']
    has_special = any(c in special_chars for c in password)
    if has_special:
        requirements_met += 1
    elif PASSWORD_CONFIG['require_special_char']:
        requirements_messages.append(
            PASSWORD_ERROR_MESSAGES['require_special_char'].format(chars=special_chars)
        )
 
    min_requirements = PASSWORD_CONFIG['min_requirements']
    if requirements_met < min_requirements:
        return False, PASSWORD_ERROR_MESSAGES['min_requirements'].format(
            min_requirements=min_requirements
        )
    
    return True, ""

def generate_salt():
    return secrets.token_hex(16)

def hash_password(password, salt):
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    h = hmac.new(salt, password, hashlib.sha256)
    return h.hexdigest()

def verify_password(stored_password, stored_salt, provided_password):
    hashed_password = hash_password(provided_password, stored_salt)
    return hmac.compare_digest(hashed_password, stored_password)

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    if not user:
        session.clear()
        flash('User not found. Please login again.')
        return redirect(url_for('login'))
    
    return render_template('home.html', username=user['username'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Username and password are required')
            return render_template('login.html')

        username = re.sub(r'[;\'"\\]', '', username)
        password = re.sub(r'[;\'"\\]', '', password)

        conn = get_db_connection()

        try:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

            if user:
                user_id = user['id']
                if 'login_attempts' in session:
                    all_attempts = session['login_attempts']
                    user_attempts = all_attempts.get(str(user_id), {'count': 0, 'block_time': 0})
                    
                    if user_attempts['count'] >= LOGIN_CONFIG['max_attempts']:
                        block_time = user_attempts['block_time']
                        current_time = time.time()
                        if current_time - block_time < LOGIN_CONFIG['block_duration']:
                            remaining_time = int(LOGIN_CONFIG['block_duration'] - (current_time - block_time))
                            flash(f'This account is temporarily blocked. Please try again in {remaining_time} seconds.')
                            return render_template('login.html')
                        else:
                            all_attempts[str(user_id)] = {'count': 0, 'block_time': 0}
                            session['login_attempts'] = all_attempts

                # Check for valid temporary password
                temp_reset = conn.execute('''
                    SELECT * FROM password_resets 
                    WHERE user_id = ? AND used = 0 AND expires_at > datetime('now')
                    ORDER BY created_at DESC LIMIT 1
                ''', (user_id,)).fetchone()

                if temp_reset:
                    # Hash the provided password and compare with stored hash
                    hashed_input = hashlib.sha1(password.encode()).hexdigest()
                    if hashed_input == temp_reset['token']:
                        # Temporary password matches, redirect to password reset
                        session['reset_user_id'] = user_id
                        conn.close()
                        return redirect(url_for('reset_password'))
                
                # Normal password verification
                if verify_password(user['password'], user['salt'], password):
                    if 'login_attempts' in session:
                        all_attempts = session['login_attempts']
                        all_attempts[str(user['id'])] = {'count': 0, 'block_time': 0}
                        session['login_attempts'] = all_attempts
                    
                    session.clear()
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['email'] = user['email']
                    flash(f"Welcome, {user['username']}!")
                    conn.close()
                    return redirect(url_for('index'))
                else:
                    all_attempts = session.get('login_attempts', {})
                    user_attempts = all_attempts.get(str(user_id), {'count': 0, 'block_time': 0})
                    user_attempts['count'] = user_attempts.get('count', 0) + 1
                    
                    if user_attempts['count'] >= LOGIN_CONFIG['max_attempts']:
                        user_attempts['block_time'] = time.time()
                        flash(f'Too many failed attempts. This account is blocked for {LOGIN_CONFIG["block_duration"]} seconds.')
                    else:
                        flash(f"Invalid username or password. {LOGIN_CONFIG['max_attempts'] - user_attempts['count']} attempts remaining.")
                    
                    all_attempts[str(user_id)] = user_attempts
                    session['login_attempts'] = all_attempts
            else:
                flash("Invalid username or password.")
        except sqlite3.Error as e:
            flash(f"Database error: {str(e)}")
        finally:
            conn.close()

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if not username or not email or not password:
            flash('All fields are required')
            return render_template('register.html')
        
        username = re.sub(r'[;\'"\\]', '', username)
        email = re.sub(r'[;\'"\\]', '', email)
        password = re.sub(r'[;\'"\\]', '', password)
        
        is_valid, error_message = validate_password(password)
        if not is_valid:
            flash(error_message)
            return render_template('register.html')

        conn = get_db_connection()
        
        try:
            existing_user = conn.execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone()
            
            if existing_user:
                flash('Username already exists')
                return render_template('register.html')
            
            salt = generate_salt()
            hashed_password = hash_password(password, salt)
            
            conn.execute('INSERT INTO users (username, email, password, salt) VALUES (?, ?, ?, ?)',
                        (username, email, hashed_password, salt))
            conn.commit()
            conn.close()
            
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
            
        except sqlite3.Error as e:
            conn.close()
            flash(f'Database error: {str(e)}')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out')
    return redirect(url_for('login'))


@app.route('/customers')
def customers():
    if 'user_id' not in session:
        flash('You must be logged in to view customers')
        return redirect(url_for('login'))
    conn = get_db_connection()
    user_customers = conn.execute(f"SELECT * FROM customers WHERE user_id = {session['user_id']} ORDER BY created_at DESC").fetchall()
    conn.close()

    customers_list = []
    for customer in user_customers:
        customers_list.append(dict(customer))
    
    return render_template('customers.html', customers=customers_list)

def html_encode(text):
    if text is None:
        return ""
    return html.escape(str(text), quote=True)

@app.route('/add_customer', methods=['GET', 'POST'])
def add_customer():
    if 'user_id' not in session:
        flash('You must be logged in to add customers')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        customer_name = request.form['name']
        
        if not customer_name:
            flash('Customer name is required')
            return redirect(url_for('add_customer'))
        
        customer_name = re.sub(r'[;\'"\\]', '', customer_name)
        

        customer_name = html_encode(customer_name)
        
        conn = get_db_connection()
        
        try:
            conn.execute('INSERT INTO customers (name, user_id) VALUES (?, ?)',
                        (customer_name, session['user_id']))
            conn.commit()
            last_customer = conn.execute(
                'SELECT * FROM customers WHERE name = ? AND user_id = ? ORDER BY id DESC LIMIT 1',
                (customer_name, session['user_id'])
            ).fetchone()
            
            conn.close()
            
            if last_customer:
                customer_id = last_customer['id']
                flash('Customer added successfully!')
                return redirect(url_for('view_customer', customer_id=customer_id))
            else:
                flash('Customer added but could not be retrieved')
                return redirect(url_for('index'))
            
        except sqlite3.Error as e:
            conn.close()
            flash(f'Database error: {str(e)}')
            return redirect(url_for('add_customer'))
    
    return render_template('add_customer.html')

@app.route('/customer/<int:customer_id>')
def view_customer(customer_id):
    if 'user_id' not in session:
        flash('You must be logged in to view customers')
        return redirect(url_for('login'))
    
    conn = get_db_connection()

    customer = conn.execute(f"SELECT * FROM customers WHERE id = {customer_id}").fetchone()
    conn.close()
    
    if not customer:
        flash('Customer not found')
        return redirect(url_for('add_customer'))
    

    customer_dict = dict(customer)
    

    
    return render_template('view_customer.html', customer=customer_dict)

@app.route('/clear_customers', methods=['POST'])
def clear_customers():
    if 'user_id' not in session:
        flash('You must be logged in to delete customers')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    try:
        conn.execute("DELETE FROM customers WHERE user_id = ?", (session['user_id'],))
        conn.commit()
        conn.close()
        
        flash('All customers have been deleted')
    except sqlite3.Error as e:
        conn.close()
        flash(f'Error deleting customers: {str(e)}')
    
    return redirect(url_for('add_customer'))

@app.route('/clear_customers_confirm')
def clear_customers_confirm():
    if 'user_id' not in session:
        flash('You must be logged in to delete customers')
        return redirect(url_for('login'))
    
    return render_template('clear_customers.html')

def generate_temp_password():
    # Generate a random 8-character temporary password
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'
    temp_password = ''.join(secrets.choice(chars) for _ in range(8))
    # Create SHA-1 hash of the temporary password
    hashed_temp = hashlib.sha1(temp_password.encode()).hexdigest()
    return temp_password, hashed_temp

def send_reset_email(email, temp_password, hashed_temp):
    if not all([SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD]):
        print("Error: SMTP settings are not properly configured")
        print(f"SMTP_SERVER: {SMTP_SERVER}")
        print(f"SMTP_PORT: {SMTP_PORT}")
        print(f"SMTP_USERNAME: {SMTP_USERNAME}")
        print(f"SMTP_PASSWORD: {'*' * len(SMTP_PASSWORD) if SMTP_PASSWORD else 'Not set'}")
        return False
        
    msg = MIMEMultipart()
    msg['From'] = SMTP_USERNAME
    msg['To'] = email
    msg['Subject'] = 'Temporary Password'
    
    body = f"""
    Hello,
    
    You have requested to reset your password. Please use the following temporary password to login:
    
    {temp_password}
    
    After logging in with this temporary password, you will be prompted to set a new password.
    This temporary password will expire in 1 hour.
    
    If you did not request this password reset, please ignore this email.
    
    Best regards,
    Your Application Team
    """
    
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        print(f"Attempting to connect to SMTP server: {SMTP_SERVER}:{SMTP_PORT}")
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.set_debuglevel(1)  # Enable debug output
        print("Starting TLS...")
        server.starttls()
        print("TLS started successfully")
        print(f"Attempting to login with username: {SMTP_USERNAME}")
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        print("Login successful")
        print(f"Sending email to: {email}")
        server.send_message(msg)
        print("Message sent successfully")
        server.quit()
        return True
    except smtplib.SMTPAuthenticationError as e:
        print(f"SMTP Authentication Error: {str(e)}")
        print("Please check your SMTP username and password")
        return False
    except smtplib.SMTPConnectError as e:
        print(f"SMTP Connection Error: {str(e)}")
        print("Please check your SMTP server and port")
        return False
    except smtplib.SMTPException as e:
        print(f"SMTP Error: {str(e)}")
        return False
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return False

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection()
        user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        
        if user:
            # Generate temporary password and its hash
            temp_password, hashed_temp = generate_temp_password()
            expires_at = datetime.now() + timedelta(hours=1)
            
            # Store hashed temporary password in database
            conn.execute('''
                INSERT INTO password_resets (user_id, token, expires_at)
                VALUES (?, ?, ?)
            ''', (user['id'], hashed_temp, expires_at))
            conn.commit()
            
            # Send email with the actual temporary password (not the hash)
            if send_reset_email(email, temp_password, hashed_temp):
                flash('A temporary password has been sent to your email. Please use it to login.')
            else:
                flash('Failed to send email. Please try again later.')
        else:
            # For non-existing users, just show the same message without doing anything
            flash('A temporary password has been sent to your email. Please use it to login.')
        
        conn.close()
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

def check_password_history(user_id, new_password, new_salt):
    conn = get_db_connection()
    try:
        # Get the last 3 passwords for this user
        history = conn.execute('''
            SELECT password, salt 
            FROM password_history 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 3
        ''', (user_id,)).fetchall()
        
        # Check if the new password matches any of the previous passwords
        for old_password in history:
            if verify_password(old_password['password'], old_password['salt'], new_password):
                return False, "Password cannot be one of your last 3 passwords."
        
        return True, ""
    finally:
        conn.close()

def add_to_password_history(user_id, password, salt):
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO password_history (user_id, password, salt)
            VALUES (?, ?, ?)
        ''', (user_id, password, salt))
        conn.commit()
    finally:
        conn.close()

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_user_id' not in session:
        flash('Please enter the reset code first.')
        return redirect(url_for('enter_reset_code'))
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('Passwords do not match.')
            return render_template('reset_password.html')
        
        is_valid, error_message = validate_password(new_password)
        if not is_valid:
            flash(error_message)
            return render_template('reset_password.html')
        
        conn = get_db_connection()
        
        # Check password history
        is_allowed, history_error = check_password_history(session['reset_user_id'], new_password, None)
        if not is_allowed:
            flash(history_error)
            return render_template('reset_password.html')
        
        # Update password
        salt = generate_salt()
        hashed_password = hash_password(new_password, salt)
        
        # Add current password to history before updating
        current_user = conn.execute('SELECT password, salt FROM users WHERE id = ?', 
                                  (session['reset_user_id'],)).fetchone()
        if current_user:
            add_to_password_history(session['reset_user_id'], 
                                  current_user['password'], 
                                  current_user['salt'])
        
        # Update the password
        conn.execute('''
            UPDATE users 
            SET password = ?, salt = ?
            WHERE id = ?
        ''', (hashed_password, salt, session['reset_user_id']))
        
        # Mark all reset codes for this user as used
        conn.execute('''
            UPDATE password_resets
            SET used = 1
            WHERE user_id = ?
        ''', (session['reset_user_id'],))
        
        conn.commit()
        conn.close()
        
        # Clear the reset session
        session.pop('reset_user_id', None)
        
        flash('Your password has been reset successfully. Please login with your new password.')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')

if __name__ == '__main__':
    init_db()
    
    app.run(debug=True, port=5000)