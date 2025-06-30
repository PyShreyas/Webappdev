from forms import LoginForm
from flask import Flask, render_template, request, redirect, session, flash, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import re
import os
import random
from forms import LoginForm  

from flask_wtf.csrf import CSRFError

app = Flask(__name__)
app.secret_key = os.urandom(24)

DB_NAME = 'database.db'
OTP_STORE = {}  # Temporarily stores OTPs


# Initialize the database
def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            email TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL)''')


# Home redirects to login
@app.route('/')
def home():
    return redirect('/login')


# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        if not re.match(r'^[\w.@+-]{3,30}$', username):
            flash("Invalid username format.")
            return redirect('/signup')

        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            flash("Invalid email address.")
            return redirect('/signup')

        if len(password) < 6:
            flash("Password must be at least 6 characters.")
            return redirect('/signup')

        hashed_pw = generate_password_hash(password)

        try:
            with sqlite3.connect(DB_NAME) as conn:
                cur = conn.cursor()
                cur.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, hashed_pw))
                conn.commit()
            flash("Signup successful. Please log in.")
            return redirect('/login')
        except sqlite3.IntegrityError:
            flash("Username or email already exists.")
            return redirect('/signup')
    return render_template('signup.html')


# Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        with sqlite3.connect(DB_NAME) as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cur.fetchone()

        if user and check_password_hash(user[3], password):  # Assuming user[3] is password
            session['user'] = user[1]  # Assuming user[1] is username
            flash("Login successful!")
            return redirect('/dashboard')
        else:
            flash("Invalid username or password", "danger")

    return render_template("login.html", form=form)

        if user and check_password_hash(user[3], password):  # password is in 4th column
            session['user'] = user[1]  # store username in session
            flash("Login successful!", "success")
            return redirect('/dashboard')
        else:
            flash("Invalid credentials.", "danger")
            return redirect('/login')

    return render_template("login.html", form=form)


# Forgot Password
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip()
        with sqlite3.connect(DB_NAME) as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = cur.fetchone()

        if user:
            otp = str(random.randint(100000, 999999))
            OTP_STORE[email] = otp
            send_email(email, otp)
            flash("OTP sent to your email.")
            return redirect(url_for('reset_password', email=email))
        else:
            flash("Email not found.")
            return redirect('/forgot-password')
    return render_template('forgot_password.html')


# Reset Password
@app.route('/reset-password/<email>', methods=['GET', 'POST'])
def reset_password(email):
    if request.method == 'POST':
        entered_otp = request.form['otp'].strip()
        new_password = request.form['new_password'].strip()
        if OTP_STORE.get(email) == entered_otp:
            hashed_pw = generate_password_hash(new_password)
            with sqlite3.connect(DB_NAME) as conn:
                conn.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_pw, email))
            flash("Password reset successful. Please login.")
            OTP_STORE.pop(email)
            return redirect('/login')
        else:
            flash("Invalid OTP.")
            return redirect(url_for('reset_password', email=email))
    return render_template('reset_password.html', email=email)


# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash("Please login first.")
        return redirect('/login')
    return render_template('dashboard.html', username=session['user'])


# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash("You've logged out successfully.")
    return redirect('/login')


# Email sending mock
def send_email(to_email, otp):
    print(f"Sending OTP {otp} to {to_email} (mock email)")


# CSRF error handler
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf_error.html', reason=e.description), 400


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
