from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = "secretkey123"
bcrypt = Bcrypt(app)

# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ---------------- HOME ----------------
@app.route('/')
def home():
    return redirect('/login')

# ---------------- REGISTER ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # EMPTY CHECK
        if username == "" or password == "":
            flash("Fields cannot be empty", "danger")
            return redirect('/register')

        # PASSWORD STRENGTH CHECK
        if len(password) < 6:
            flash("Password must be at least 6 characters", "danger")
            return redirect('/register')

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = sqlite3.connect('users.db')
        c = conn.cursor()

        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                      (username, hashed_password))
            conn.commit()
        except:
            flash("Username already exists", "danger")
            return redirect('/register')

        conn.close()
        flash("Registration successful!", "success")
        return redirect('/login')

    return render_template('register.html')

# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # EMPTY CHECK
        if username == "" or password == "":
            flash("Fields cannot be empty", "danger")
            return redirect('/login')

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user[2], password):
            session['user'] = username
            session['otp'] = "1234"
            return redirect('/otp')

        flash("Invalid username or password", "danger")
        return redirect('/login')

    return render_template('login.html')

# ---------------- OTP ----------------
@app.route('/otp', methods=['GET', 'POST'])
def otp():
    if request.method == 'POST':
        if request.form['otp'] == session.get('otp'):
            return redirect('/dashboard')
        return "Invalid OTP"

    return render_template('otp.html')

# ---------------- DASHBOARD ----------------
@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return render_template('dashboard.html', user=session['user'])
    return redirect('/login')

# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

# ---------------- RUN APP ----------------
if __name__ == '__main__':
    app.run(debug=True)