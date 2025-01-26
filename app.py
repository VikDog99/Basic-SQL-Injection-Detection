from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Database initialization
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    firstname TEXT,
                    lastname TEXT,
                    username TEXT UNIQUE,
                    phone TEXT,
                    email TEXT UNIQUE,
                    password TEXT
                )''')
    conn.commit()
    conn.close()

# Function to detect SQL injection
def detect_sql_injection(input_text):
    sql_injection_patterns = [
        r"(--|;|#)",  # Comments
        r"(\bOR\b.*?=)",  # OR clause
        r"(\bAND\b.*?=)",  # AND clause
        r"(UNION\s+SELECT)",  # UNION SELECT clause
        r"(\bSELECT\b.*?\bFROM\b)",  # SELECT FROM clause
        r"(\bINSERT\b.*?\bINTO\b)",  # INSERT INTO clause
        r"(\bDROP\b.*?\bTABLE\b)",  # DROP TABLE clause
        r"(\bDELETE\b.*?\bFROM\b)"  # DELETE FROM clause
    ]

    for pattern in sql_injection_patterns:
        if re.search(pattern, input_text, re.IGNORECASE):
            return True
    return False


# Home route
@app.route('/')
def index():
    return render_template('index.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if detect_sql_injection(username) or detect_sql_injection(password):
            flash("SQL Injection detected! Invalid input.", "error")
            return redirect(url_for('login'))

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[6], password):  # Check hashed password
            session['username'] = username
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.", "error")

    return render_template('login.html')

# Sign up route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        username = request.form['username']
        phone = request.form['phone']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if detect_sql_injection(username) or detect_sql_injection(email):
            flash("SQL Injection detected! Invalid input.", "error")
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)  # Hash the password

        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (firstname, lastname, username, phone, email, password) VALUES (?, ?, ?, ?, ?, ?)",
                      (firstname, lastname, username, phone, email, hashed_password))
            conn.commit()
            conn.close()
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username or email already exists!", "error")

    return render_template('signup.html')

# Dashboard route
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        flash("Please log in to access the dashboard.", "error")
        return redirect(url_for('login'))

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You have been logged out.", "success")
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

