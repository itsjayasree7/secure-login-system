# 🔐 Secure Login System

A Flask-based secure web application with hashed passwords, SQL injection protection, session management, and optional Two-Factor Authentication (2FA).

---

## 📋 Features

- **Password Hashing** — Passwords hashed with `bcrypt` (never stored in plain text)
- **SQL Injection Protection** — All database queries use parameterized statements
- **Input Validation** — Username, email, and password strength enforced server-side
- **Session Management** — Secure sessions with 30-minute timeout and logout
- **Two-Factor Authentication (2FA)** — Optional TOTP-based 2FA via Google Authenticator or Authy
- **Clean UI** — Dark-themed responsive interface

---

## 🛠️ Tech Stack

- Python 3.x / Flask
- SQLite (via `sqlite3`)
- bcrypt (password hashing)
- pyotp + qrcode (2FA)
- HTML / CSS (Jinja2 templates)

---

## ⚙️ Installation

**1. Clone the repository**
```bash
git clone https://github.com/itsjayasree7/secure-login-system.git
cd secure-login-system
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

**3. Run the app**
```bash
python app.py
```

**4. Open in browser**
```
http://127.0.0.1:5000
```

---

## 🔒 Security Features

| Feature | Implementation |
|---|---|
| Password Hashing | bcrypt with salt |
| SQL Injection | Parameterized queries |
| Session Timeout | 30 minutes |
| Password Policy | Min 8 chars, uppercase, number, special char |
| 2FA | TOTP (RFC 6238) via pyotp |

---

## 📁 Project Structure

```
secure-login-system/
│
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── README.md               # Project documentation
└── templates/
    ├── base.html           # Base layout
    ├── register.html       # Registration page
    ├── login.html          # Login page
    ├── dashboard.html      # User dashboard
    ├── setup_2fa.html      # 2FA setup page
    └── verify_2fa.html     # 2FA verification page
```

---

## 🔐 Ethical Usage

This project is intended for **educational purposes only**.  
Do not deploy this in production without additional security hardening.

---

