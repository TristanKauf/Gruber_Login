# Login-Aufgabe: drei aufbauende Lösungen

## Sicherheitsstufen

`AUTH_LEVEL=1`: E-Mail + Passwort.

`AUTH_LEVEL=2`: E-Mail + Passwort + einmaliger Bestätigungscode per E-Mail.

`AUTH_LEVEL=3`: E-Mail + Passwort + E-Mail-Code + zeitbasiertes OTP (TOTP).

Die Datenbank speichert E-Mail, Passwort-Hash, `password_changed_at`, `last_login_at`, Reset-Daten und den TOTP-Schlüssel. Das Passwort wird im Browser vor dem Absenden mit SHA-256 in einen Client-Schlüssel umgewandelt. Der Server speichert davon nur einen langsamen Salted-Hash (scrypt in Python, password_hash in PHP), niemals ein Passwort im Klartext. In Produktion sind HTTPS, echte E-Mail-Zustellung, Rate-Limiting, generische Reset-Meldungen und eine echte Authenticator-App erforderlich.

## PythonAnywhere / Python

```powershell
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
$env:AUTH_LEVEL=3
py python_app.py
```

Lokal: `http://127.0.0.1:5000`. Den E-Mail-Code zeigt die Demo im Terminal. Für PythonAnywhere `python_app.py` als Flask-App eintragen, `requirements.txt` installieren und den `SECRET_KEY` als Umgebungsvariable setzen.

## XAMPP / PHP

1. Den Ordner `php` nach `C:\xampp\htdocs\login` kopieren.
2. In `php/config.php` `AUTH_LEVEL` auf `1`, `2` oder `3` setzen.
3. Apache in XAMPP starten.
4. `http://127.0.0.1/login/` öffnen. Bei Port 8080: `http://127.0.0.1:8080/login/`.

Für SQLite muss in `php.ini` `pdo_sqlite` aktiviert sein. Der Demo-E-Mail-Code steht im Apache/PHP-Log.

## Bonus: Passwort zurücksetzen

Der Reset-Baustein ist in der Python-Version vollständig enthalten und zeigt den Link aus Sicherheitsgründen nur als lokale Demo-Meldung. Für PHP wird dieselbe Struktur empfohlen: zufälliges Token, nur dessen Hash in der Datenbank, Ablaufzeit 15 Minuten und Link per Mail.
