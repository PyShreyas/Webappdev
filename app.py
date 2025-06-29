from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import re
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

DB_NAME = 'database.db'

def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL)''')

@app.route('/')
def home():
    return redirect('/login')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        if not re.match(r'^[\w.@+-]{3,30}$', username):
            flash("Invalid username format.")
            return redirect('/signup')

        if len(password) < 6:
            flash("Password must be at least 6 characters.")
            return redirect('/signup')

        hashed_pw = generate_password_hash(password)

        try:
            with sqlite3.connect(DB_NAME) as conn:
                cur = conn.cursor()
                cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
                conn.commit()
            flash("Signup successful. Please log in.")
            return redirect('/login')
        except sqlite3.IntegrityError:
            flash("Username already exists.")
            return redirect('/signup')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        with sqlite3.connect(DB_NAME) as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cur.fetchone()

        if user and check_password_hash(user[2], password):
            session['user'] = user[1]
            flash("Login successful!")
            return redirect('/dashboard')
        else:
            flash("Invalid credentials.")
            return redirect('/login')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash("Please login first.")
        return redirect('/login')
    return render_template('dashboard.html', username=session['user'])

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.")
    return redirect('/login')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
