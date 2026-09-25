import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, flash, redirect, render_template_string, request, session, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "change-this-local-secret")
DB = os.path.join(os.path.dirname(__file__), "login.sqlite3")
AUTH_LEVEL = int(os.environ.get("AUTH_LEVEL", "3"))
LOGIN_WINDOW_MINUTES = 15

HTML = """<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Secure Login</title>
<style>body{font:16px system-ui;margin:3rem auto;max-width:540px;padding:0 1rem;background:#f4f6f8;color:#17212b}main{background:white;padding:2rem;border-radius:12px;box-shadow:0 8px 30px #0001}label{display:block;margin-top:1rem;font-weight:600}input,button{box-sizing:border-box;width:100%;padding:.7rem;margin-top:.35rem;border:1px solid #bbc5ce;border-radius:6px}button{background:#1769aa;color:#fff;border:0;margin-top:1.3rem;cursor:pointer}.flash{padding:.7rem;background:#fff2cc;border-left:4px solid #d99b00}a{color:#1769aa}.meta{color:#5d6872;font-size:.9rem}</style></head>
<body><main><h1>Secure Login</h1><p class="meta">Stufe {{ level }} von 3</p>{% for message in get_flashed_messages() %}<p class="flash">{{ message }}</p>{% endfor %}"""


def db():
    connection = sqlite3.connect(DB)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with db() as connection:
        connection.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, password_changed_at TEXT NOT NULL,
            last_login_at TEXT, reset_token_hash TEXT, reset_expires_at TEXT,
            totp_secret TEXT NOT NULL)""")


def now():
    return datetime.now(timezone.utc).isoformat()


def hash_secret(value):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(value.encode(), salt=salt, n=2**14, r=8, p=1)
    return base64.b64encode(salt + digest).decode()


def verify_secret(value, stored):
    raw = base64.b64decode(stored)
    salt, expected = raw[:16], raw[16:]
    actual = hashlib.scrypt(value.encode(), salt=salt, n=2**14, r=8, p=1)
    return hmac.compare_digest(actual, expected)


def client_secret(password):
    return hashlib.sha256(password.encode()).hexdigest()


def make_totp(secret, at=None):
    counter = int((at or time.time()) // 30).to_bytes(8, "big")
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 15
    number = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff) % 1000000
    return f"{number:06d}"


def send_email_code(email, code):
    print(f"[DEMO MAIL] Login-Code fuer {email}: {code}")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = client_secret(request.form["password"])
        user = db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if not user or not verify_secret(password, user["password_hash"]):
            flash("E-Mail oder Passwort ist falsch.")
            return redirect(url_for("login"))
        session["pending_user"] = user["id"]
        if AUTH_LEVEL >= 2:
            code = f"{secrets.randbelow(1000000):06d}"
            session["email_code"] = code
            session["email_code_expires"] = time.time() + 300
            send_email_code(email, code)
            return redirect(url_for("email_code"))
        if AUTH_LEVEL >= 3:
            return redirect(url_for("totp"))
        session["user_id"] = user["id"]
        return redirect(url_for("dashboard"))
    return render_template_string(HTML + """<form method="post" onsubmit="return protect(this)"><label>E-Mail<input type="email" name="email" required></label><label>Passwort<input type="password" name="password" required></label><button>Anmelden</button></form><p><a href="{{ url_for('register') }}">Konto anlegen</a> · <a href="{{ url_for('reset') }}">Passwort vergessen?</a></p><script>async function protect(f){const p=f.password;const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(p.value));p.value=Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join('');return true}</script></main></body></html>""", level=AUTH_LEVEL)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        secret = client_secret(request.form["password"])
        totp_secret = base64.b32encode(secrets.token_bytes(10)).decode().rstrip("=")
        try:
            with db() as connection:
                connection.execute("INSERT INTO users(email,password_hash,password_changed_at,totp_secret) VALUES(?,?,?,?)", (email, hash_secret(secret), now(), totp_secret))
            flash("Konto erstellt. Dein TOTP-Schluessel fuer die Demo: " + totp_secret)
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Diese E-Mail ist bereits registriert.")
    return render_template_string(HTML + """<h2>Konto anlegen</h2><form method="post" onsubmit="return protect(this)"><label>E-Mail<input type="email" name="email" required></label><label>Passwort<input type="password" name="password" minlength="8" required></label><button>Registrieren</button></form><p><a href="{{ url_for('login') }}">Zur Anmeldung</a></p><script>async function protect(f){const p=f.password;const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(p.value));p.value=Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join('');return true}</script></main></body></html>""", level=AUTH_LEVEL)


@app.route("/email-code", methods=["GET", "POST"])
def email_code():
    if request.method == "POST":
        if time.time() > session.get("email_code_expires", 0) or not hmac.compare_digest(request.form["code"], session.get("email_code", "")):
            flash("Der Bestätigungscode ist ungültig oder abgelaufen.")
            return redirect(url_for("email_code"))
        if AUTH_LEVEL >= 3:
            return redirect(url_for("totp"))
        session["user_id"] = session.pop("pending_user")
        return redirect(url_for("dashboard"))
    return render_template_string(HTML + """<h2>E-Mail bestätigen</h2><p>Der Demo-Code steht im Python-Terminal.</p><form method="post"><label>6-stelliger Code<input name="code" inputmode="numeric" pattern="[0-9]{6}" required></label><button>Prüfen</button></form></main></body></html>""", level=AUTH_LEVEL)


@app.route("/totp", methods=["GET", "POST"])
def totp():
    if request.method == "POST":
        user = db().execute("SELECT * FROM users WHERE id = ?", (session.get("pending_user"),)).fetchone()
        if user and hmac.compare_digest(request.form["code"], make_totp(user["totp_secret"])):
            session["user_id"] = session.pop("pending_user")
            return redirect(url_for("dashboard"))
        flash("OTP ist falsch. In der Demo ist der aktuelle Code: " + (make_totp(user["totp_secret"]) if user else "unbekannt"))
    return render_template_string(HTML + """<h2>OTP Authenticator</h2><p>Gib den aktuellen 6-stelligen Code aus deiner Authenticator-App ein.</p><form method="post"><label>OTP<input name="code" inputmode="numeric" pattern="[0-9]{6}" required></label><button>Einloggen</button></form></main></body></html>""", level=AUTH_LEVEL)


@app.route("/dashboard")
@login_required
def dashboard():
    with db() as connection:
        connection.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now(), session["user_id"]))
        user = connection.execute("SELECT email,last_login_at FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return render_template_string(HTML + """<h2>Angemeldet</h2><p>{{ user['email'] }}</p><p class="meta">Letzter Login: {{ user['last_login_at'] }}</p><p><a href="{{ url_for('logout') }}">Abmelden</a></p></main></body></html>""", user=user, level=AUTH_LEVEL)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/reset", methods=["GET", "POST"])
def reset():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        user = db().execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if user:
            raw = secrets.token_urlsafe(24)
            with db() as connection:
                connection.execute("UPDATE users SET reset_token_hash=?,reset_expires_at=? WHERE id=?", (hash_secret(raw), time.time() + 900, user["id"]))
            flash("[DEMO] Reset-Link: /reset-password?token=" + raw)
        else:
            flash("Wenn die E-Mail existiert, wurde ein Reset-Link versendet.")
    return render_template_string(HTML + """<h2>Passwort zurücksetzen</h2><form method="post"><label>E-Mail<input type="email" name="email" required></label><button>Reset-Link anfordern</button></form></main></body></html>""", level=AUTH_LEVEL)


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    token = request.args.get("token", "")
    if request.method == "POST":
        token = request.form["token"]
        user = db().execute("SELECT * FROM users WHERE reset_expires_at > ?", (time.time(),)).fetchall()
        match = next((row for row in user if verify_secret(token, row["reset_token_hash"])), None)
        if match:
            with db() as connection:
                connection.execute("UPDATE users SET password_hash=?,password_changed_at=?,reset_token_hash=NULL,reset_expires_at=NULL WHERE id=?", (hash_secret(client_secret(request.form["password"])), now(), match["id"]))
            flash("Passwort geändert.")
            return redirect(url_for("login"))
        flash("Reset-Link ist ungültig oder abgelaufen.")
    return render_template_string(HTML + """<h2>Neues Passwort</h2><form method="post" onsubmit="return protect(this)"><input type="hidden" name="token" value="{{ token }}"><label>Passwort<input type="password" name="password" minlength="8" required></label><button>Passwort speichern</button></form><script>async function protect(f){const p=f.password;const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(p.value));p.value=Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join('');return true}</script></main></body></html>""", token=token, level=AUTH_LEVEL)


init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
