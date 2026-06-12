"""
Secure Login System
A Flask web app with hashed passwords, SQL injection protection,
session management, and optional Two-Factor Authentication (2FA).
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import bcrypt
import os
import re
import secrets
import pyotp
import qrcode
import io
import base64
from datetime import timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.permanent_session_lifetime = timedelta(minutes=30)

DB_PATH = "users.db"


# ─────────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT,
                two_fa_enabled INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


# ─────────────────────────────────────────────
# INPUT VALIDATION (SQL Injection Protection)
# ─────────────────────────────────────────────

def is_valid_username(username):
    """Allow only alphanumeric and underscores, 3-20 chars."""
    return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', username))

def is_valid_email(email):
    return bool(re.match(r'^[\w\.-]+@[\w\.-]+\.\w{2,}$', email))

def is_strong_password(password):
    """Minimum 8 chars, 1 uppercase, 1 digit, 1 special char."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number."
    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        return False, "Password must contain at least one special character."
    return True, "OK"


# ─────────────────────────────────────────────
# LOGIN REQUIRED DECORATOR
# ─────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        # Validate inputs
        if not is_valid_username(username):
            flash("Username must be 3-20 characters (letters, numbers, underscores only).", "danger")
            return render_template("register.html")
        if not is_valid_email(email):
            flash("Invalid email address.", "danger")
            return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")
        valid, msg = is_strong_password(password)
        if not valid:
            flash(msg, "danger")
            return render_template("register.html")

        # Hash password with bcrypt
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        # Parameterized query — prevents SQL injection
        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email, password_hash)
                )
                conn.commit()
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "danger")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please fill in all fields.", "danger")
            return render_template("login.html")

        # Parameterized query — prevents SQL injection
        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

        if user and bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
            if user["two_fa_enabled"]:
                # Store temp session for 2FA verification
                session["temp_user_id"] = user["id"]
                session["temp_username"] = user["username"]
                return redirect(url_for("verify_2fa"))
            else:
                session.permanent = True
                session["user_id"]  = user["id"]
                session["username"] = user["username"]
                flash(f"Welcome back, {user['username']}! 👋", "success")
                return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    if "temp_user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        otp_code = request.form.get("otp_code", "").strip()
        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE id = ?", (session["temp_user_id"],)
            ).fetchone()

        if user:
            totp = pyotp.TOTP(user["totp_secret"])
            if totp.verify(otp_code):
                session.permanent = True
                session["user_id"]  = user["id"]
                session["username"] = user["username"]
                session.pop("temp_user_id", None)
                session.pop("temp_username", None)
                flash(f"Welcome back, {user['username']}! 👋", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid 2FA code. Please try again.", "danger")

    return render_template("verify_2fa.html")


@app.route("/dashboard")
@login_required
def dashboard():
    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
    return render_template("dashboard.html", user=user)


@app.route("/setup-2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()

    if request.method == "POST":
        otp_code   = request.form.get("otp_code", "").strip()
        totp_secret = request.form.get("totp_secret", "")
        totp = pyotp.TOTP(totp_secret)
        if totp.verify(otp_code):
            with get_db() as conn:
                conn.execute(
                    "UPDATE users SET totp_secret = ?, two_fa_enabled = 1 WHERE id = ?",
                    (totp_secret, session["user_id"])
                )
                conn.commit()
            flash("Two-Factor Authentication enabled successfully! 🔐", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid code. Please scan the QR code again and retry.", "danger")
            return redirect(url_for("setup_2fa"))

    # Generate new TOTP secret and QR code
    totp_secret = pyotp.random_base32()
    totp_uri    = pyotp.TOTP(totp_secret).provisioning_uri(
        name=user["email"], issuer_name="SecureLoginApp"
    )
    img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return render_template("setup_2fa.html", qr_code=qr_b64, totp_secret=totp_secret)


@app.route("/disable-2fa", methods=["POST"])
@login_required
def disable_2fa():
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET totp_secret = NULL, two_fa_enabled = 0 WHERE id = ?",
            (session["user_id"],)
        )
        conn.commit()
    flash("Two-Factor Authentication disabled.", "info")
    return redirect(url_for("dashboard"))


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("login"))


# ─────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print("\n╔══════════════════════════════════════════╗")
    print("║        Secure Login System               ║")
    print("║  Running at http://127.0.0.1:5000        ║")
    print("╚══════════════════════════════════════════╝\n")
    app.run(debug=True)
