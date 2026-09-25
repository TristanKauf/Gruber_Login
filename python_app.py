"""Small three-level login application with SMTP email delivery."""

import base64
import configparser
import hashlib
import hmac
import io
import os
import secrets
import smtplib
import sqlite3
import time
import urllib.parse
from datetime import datetime, timezone
from email.message import EmailMessage
from functools import wraps

from flask import Flask, flash, redirect, render_template_string, request, session, url_for
from markupsafe import escape
import qrcode

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "login.sqlite3")
CONFIG_PATH = os.path.join(BASE_DIR, "config.ini")


def read_config():
    """Read editable local settings from config.ini."""
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH, encoding="utf-8")
    return config


CONFIG = read_config()


def reset_auth_level_on_start():
    """Always start the application with the basic login security level."""
    if not CONFIG.has_section("app"):
        CONFIG.add_section("app")
    CONFIG.set("app", "auth_level", "1")
    with open(CONFIG_PATH, "w", encoding="utf-8") as config_file:
        CONFIG.write(config_file)


reset_auth_level_on_start()
AUTH_LEVEL = 1
LOGIN_MINUTES = 15
CODE_MINUTES = 5
RESET_MINUTES = 15

app = Flask(__name__)
app.secret_key = CONFIG.get("app", "flask_secret", fallback="change-me-before-production")

PAGE = """<!doctype html><html lang='de'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Login</title><style>body{font:16px system-ui;max-width:520px;margin:40px auto;padding:0 16px;background:#f3f5f7}main{background:#fff;padding:28px;border-radius:10px}label{display:block;margin-top:14px;font-weight:600}input,button{width:100%;box-sizing:border-box;padding:10px;margin-top:5px}button{background:#1464a0;color:#fff;border:0;margin-top:20px;cursor:pointer}.message{padding:10px;background:#fff2c7}a{color:#1464a0}.small{color:#5b6570;font-size:.9rem}</style><main>
<h1>Login</h1><p class='small'>Sicherheitsstufe {{ level }} von 3</p>{% for message in get_flashed_messages() %}<p class='message'>{{ message }}</p>{% endfor %}{{ body|safe }}</main></html>"""

PASSWORD_SCRIPT = """<script>async function protect(form){const field=form.password;const bytes=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(field.value));field.value=Array.from(new Uint8Array(bytes),byte=>byte.toString(16).padStart(2,'0')).join('');return true}</script>"""


def connect():
    """Open the SQLite database with named-column rows."""
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    """Create the only application table if it does not exist."""
    with connect() as connection:
        connection.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, password_changed_at TEXT NOT NULL,
            last_login_at TEXT, totp_secret TEXT NOT NULL,
            reset_token_hash TEXT, reset_expires_at REAL)""")


def wipe_database_on_start():
    """Delete the local database before startup when testing is enabled."""
    if CONFIG.getboolean("app", "wipe_database_on_start", fallback=False) and os.path.exists(DB_PATH):
        os.remove(DB_PATH)


def utc_now():
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def client_password(password):
    """Create the password value sent from the browser to the server."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def hash_value(value):
    """Hash a value with a random salt and scrypt."""
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(value.encode(), salt=salt, n=2**14, r=8, p=1)
    return base64.b64encode(salt + digest).decode()


def verify_value(value, encoded):
    """Compare a value with a previously generated scrypt hash."""
    if not encoded:
        return False
    raw = base64.b64decode(encoded)
    actual = hashlib.scrypt(value.encode(), salt=raw[:16], n=2**14, r=8, p=1)
    return hmac.compare_digest(actual, raw[16:])


def totp_code(secret, timestamp=None):
    """Generate the six-digit RFC 6238-compatible TOTP code."""
    counter = int((timestamp or time.time()) // 30).to_bytes(8, "big")
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 15
    number = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff) % 1_000_000
    return f"{number:06d}"


def send_mail(recipient, subject, text):
    """Send a real email through the configured SMTP server.

    SMTP settings are read from the ``[mail]`` section in config.ini.
    """
    required = ("host", "user", "password", "from")
    missing = [name for name in required if not CONFIG.get("mail", name, fallback="")]
    if missing:
        raise RuntimeError("Fehlende Mail-Einstellungen in config.ini: " + ", ".join(missing))
    message = EmailMessage()
    message["From"] = CONFIG.get("mail", "from")
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(text)
    host = CONFIG.get("mail", "host")
    port = CONFIG.getint("mail", "port", fallback=587)
    smtp_class = smtplib.SMTP_SSL if CONFIG.get("mail", "security", fallback="starttls").lower() == "ssl" else smtplib.SMTP
    with smtp_class(host, port, timeout=20) as smtp:
        if smtp_class is smtplib.SMTP:
            smtp.starttls()
        smtp.login(CONFIG.get("mail", "user"), CONFIG.get("mail", "password"))
        smtp.send_message(message)


def page(body):
    """Render a body fragment inside the shared application layout."""
    return render_template_string(PAGE, body=body, level=AUTH_LEVEL)


def csrf_token():
    """Return the CSRF token used by settings forms."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def save_auth_level(level):
    """Save the selected security level in config.ini for future starts."""
    CONFIG.set("app", "auth_level", str(level))
    with open(CONFIG_PATH, "w", encoding="utf-8") as config_file:
        CONFIG.write(config_file)


def finish_login(user_id):
    """Turn a pending authentication into a 15-minute authenticated session."""
    session.clear()
    session["user_id"] = user_id
    session["authenticated_at"] = time.time()
    with connect() as connection:
        connection.execute("UPDATE users SET last_login_at=? WHERE id=?", (utc_now(), user_id))


def protected(view):
    """Protect a view and expire sessions after the configured time window."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session or time.time() - session.get("authenticated_at", 0) > LOGIN_MINUTES * 60:
            session.clear()
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


@app.route("/", methods=["GET", "POST"])
def login():
    """Process the password step and start level 2 or 3 when configured."""
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = client_password(request.form["password"])
        with connect() as connection:
            user = connection.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not user or not verify_value(password, user["password_hash"]):
            flash("E-Mail oder Passwort ist falsch.")
            return redirect(url_for("login"))
        if AUTH_LEVEL == 1:
            finish_login(user["id"])
            return redirect(url_for("dashboard"))
        session["pending_user"] = user["id"]
        if AUTH_LEVEL == 3:
            session["email_verified"] = True
            return redirect(url_for("otp"))
        code = f"{secrets.randbelow(1_000_000):06d}"
        session["email_code"] = hash_value(code)
        session["email_code_expires"] = time.time() + CODE_MINUTES * 60
        try:
            send_mail(email, "Dein Login-Code", f"Dein Login-Code lautet: {code}\n\nEr ist fünf Minuten gültig.")
        except (KeyError, OSError, RuntimeError, smtplib.SMTPException) as error:
            session.clear()
            app.logger.exception("SMTP delivery failed: %s", error)
            flash("Die E-Mail konnte nicht versendet werden. SMTP-Konfiguration prüfen.")
            return redirect(url_for("login"))
        return redirect(url_for("email_code"))
    body = """<form method='post' onsubmit='return protect(this)'><label>E-Mail<input type='email' name='email' required></label><label>Passwort<input type='password' name='password' required></label><button>Anmelden</button></form><p><a href='/register'>Konto anlegen</a> | <a href='/reset'>Passwort vergessen?</a></p>""" + PASSWORD_SCRIPT
    return page(body)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Create an account with a client-derived password and TOTP secret."""
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        if len(password) < 8:
            flash("Das Passwort muss mindestens acht Zeichen enthalten.")
        else:
            secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
            try:
                with connect() as connection:
                    connection.execute("INSERT INTO users(email,password_hash,password_changed_at,totp_secret) VALUES(?,?,?,?)", (email, hash_value(client_password(password)), utc_now(), secret))
                if AUTH_LEVEL == 3:
                    flash(f"Konto erstellt. TOTP-Schlüssel für deine Authenticator-App: {secret}")
                else:
                    flash("Konto erstellt.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Diese E-Mail ist bereits registriert.")
    body = """<h2>Konto anlegen</h2><form method='post' onsubmit='return protect(this)'><label>E-Mail<input type='email' name='email' required></label><label>Passwort<input type='password' name='password' minlength='8' required></label><button>Registrieren</button></form><p><a href='/'>Zur Anmeldung</a></p>""" + PASSWORD_SCRIPT
    return page(body)


@app.route("/email-code", methods=["GET", "POST"])
def email_code():
    """Verify the emailed code for security level 2."""
    if "pending_user" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        code = request.form["code"]
        valid = time.time() < session.get("email_code_expires", 0) and verify_value(code, session.get("email_code", ""))
        if not valid:
            flash("Der Code ist falsch oder abgelaufen.")
        elif AUTH_LEVEL == 2:
            finish_login(session["pending_user"])
            return redirect(url_for("dashboard"))
        else:
            return redirect(url_for("login"))
    return page("<h2>E-Mail bestätigen</h2><form method='post'><label>6-stelliger Code<input name='code' pattern='[0-9]{6}' required></label><button>Prüfen</button></form>")


@app.route("/otp", methods=["GET", "POST"])
def otp():
    """Verify the authenticator code and finish level 3 authentication."""
    if "pending_user" not in session or not session.get("email_verified"):
        return redirect(url_for("login"))
    with connect() as connection:
        user = connection.execute("SELECT * FROM users WHERE id=?", (session["pending_user"],)).fetchone()
    if request.method == "POST":
        if user and hmac.compare_digest(request.form["code"], totp_code(user["totp_secret"])):
            finish_login(user["id"])
            return redirect(url_for("dashboard"))
        flash("OTP ist falsch oder abgelaufen.")
    token = escape(user["totp_secret"]) if user else "nicht verfügbar"
    body = f"<h2>OTP Authenticator</h2><p class='small'>QR-Code mit deiner Authenticator-App scannen:</p><p><img src='{url_for('otp_qr')}' alt='QR-Code für den Authenticator' width='220' height='220'></p><p class='small'>Falls Scannen nicht funktioniert, Auth-Token manuell eingeben:</p><p><strong>{token}</strong></p><form method='post'><label>6-stelliger OTP<input name='code' pattern='[0-9]{{6}}' required></label><button>Einloggen</button></form>"
    return page(body)


@app.get("/otp-qr")
def otp_qr():
    """Return a local QR image for the pending user's authenticator setup."""
    if "pending_user" not in session or not session.get("email_verified"):
        return redirect(url_for("login"))
    with connect() as connection:
        user = connection.execute("SELECT email,totp_secret FROM users WHERE id=?", (session["pending_user"],)).fetchone()
    if not user:
        return redirect(url_for("login"))
    label = urllib.parse.quote(f"Login:{user['email']}")
    issuer = urllib.parse.quote("Login")
    otp_uri = f"otpauth://totp/{label}?secret={user['totp_secret']}&issuer={issuer}"
    image = qrcode.make(otp_uri)
    output = io.BytesIO()
    image.save(output, format="PNG")
    output.seek(0)
    return app.response_class(output.getvalue(), mimetype="image/png")


@app.route("/dashboard")
@protected
def dashboard():
    """Show the account and the stored successful-login timestamp."""
    with connect() as connection:
        user = connection.execute("SELECT email,last_login_at FROM users WHERE id=?", (session["user_id"],)).fetchone()
    body = f"<h2>Angemeldet</h2><p>{escape(user['email'])}</p><p class='small'>Letzter Login: {escape(user['last_login_at'])}</p><form method='get' action='/settings'><button type='submit'>Sicherheitsstufe ändern</button></form><p><a href='/logout'>Abmelden</a></p>"
    return page(body)


@app.route("/settings", methods=["GET", "POST"])
@protected
def settings():
    """Change the global login security level from the authenticated page."""
    global AUTH_LEVEL
    if request.method == "POST":
        if not hmac.compare_digest(request.form.get("csrf_token", ""), csrf_token()):
            flash("Ungültige Anfrage.")
            return redirect(url_for("settings"))
        try:
            level = int(request.form["auth_level"])
        except (KeyError, ValueError):
            level = 0
        if level not in (1, 2, 3):
            flash("Bitte eine Sicherheitsstufe von 1 bis 3 auswählen.")
        else:
            save_auth_level(level)
            AUTH_LEVEL = level
            flash(f"Sicherheitsstufe {level} ist aktiv.")
            return redirect(url_for("dashboard"))
    selected = {1: "", 2: "", 3: ""}
    selected[AUTH_LEVEL] = " selected"
    body = """<h2>Sicherheitsstufe</h2><form method='post'><input type='hidden' name='csrf_token' value='{}'><label>Login-Verfahren<select name='auth_level'><option value='1'{}>1: E-Mail und Passwort</option><option value='2'{}>2: zusätzlich E-Mail-Code</option><option value='3'{}>3: zusätzlich OTP-Authenticator</option></select></label><button>Speichern</button></form><p><a href='/dashboard'>Zurück</a></p>""".format(csrf_token(), selected[1], selected[2], selected[3])
    return page(body)


@app.get("/logout")
def logout():
    """End the current session."""
    session.clear()
    return redirect(url_for("login"))


@app.route("/reset", methods=["GET", "POST"])
def reset():
    """Email a real, time-limited password-reset link."""
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        with connect() as connection:
            user = connection.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if user:
            token = secrets.token_urlsafe(32)
            with connect() as connection:
                connection.execute("UPDATE users SET reset_token_hash=?,reset_expires_at=? WHERE id=?", (hash_value(token), time.time() + RESET_MINUTES * 60, user["id"]))
            try:
                link = url_for("reset_password", token=token, _external=True)
                send_mail(email, "Passwort zurücksetzen", f"Öffne diesen Link innerhalb von 15 Minuten:\n{link}")
            except (KeyError, OSError, RuntimeError, smtplib.SMTPException):
                app.logger.exception("Reset email failed")
        flash("Wenn die E-Mail existiert, wurde ein Reset-Link versendet.")
    return page("<h2>Passwort zurücksetzen</h2><form method='post'><label>E-Mail<input type='email' name='email' required></label><button>Link anfordern</button></form>")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    """Validate a reset token and save the new client-derived password."""
    token = request.values.get("token", "")
    if request.method == "POST":
        with connect() as connection:
            candidates = connection.execute("SELECT * FROM users WHERE reset_expires_at>?", (time.time(),)).fetchall()
        user = next((row for row in candidates if verify_value(token, row["reset_token_hash"])), None)
        if user and len(request.form["password"]) >= 8:
            with connect() as connection:
                connection.execute("UPDATE users SET password_hash=?,password_changed_at=?,reset_token_hash=NULL,reset_expires_at=NULL WHERE id=?", (hash_value(client_password(request.form["password"])), utc_now(), user["id"]))
            flash("Passwort geändert.")
            return redirect(url_for("login"))
        flash("Der Link ist ungültig oder das Passwort zu kurz.")
    body = "<h2>Neues Passwort</h2><form method='post' onsubmit='return protect(this)'><input type='hidden' name='token' value='" + str(escape(token)) + "'><label>Passwort<input type='password' name='password' minlength='8' required></label><button>Speichern</button></form>" + PASSWORD_SCRIPT
    return page(body)


wipe_database_on_start()
initialize_database()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=CONFIG.getint("app", "port", fallback=5000), debug=False)
