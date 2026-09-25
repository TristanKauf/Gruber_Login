# Login-Projekt

Das Projekt enthält dasselbe einfache Login-System in Python und PHP:

1. E-Mail und Passwort
2. E-Mail, Passwort und sechsstelliger Code per E-Mail
3. E-Mail, Passwort und OTP aus einer Authenticator-App

Zusätzlich gibt es Registrierung, zeitlich begrenzte Sitzungen und Passwort-Reset per E-Mail.

## 1. Einzige Konfiguration

Bearbeite vor dem Start nur [`config.ini`](config.ini):

```ini
[app]
auth_level = 1
port = 5000
flask_secret = ein-langes-zufaelliges-geheimnis
wipe_database_on_start = false

[mail]
host = smtp.example.com
port = 587
security = starttls
user = deine-adresse@example.com
password = dein-app-passwort
from = deine-adresse@example.com

[php]
app_url = http://127.0.0.1/login/php
```

`auth_level` kann `1`, `2` oder `3` sein. Setze `wipe_database_on_start = true` nur für Tests: Dann wird die Python-Datenbank bei jedem Start vollständig gelöscht. Für normale Nutzung muss der Wert `false` sein. Die Datei ist lokal und wird nicht in Git gespeichert. Für eine neue Kopie ist [`config.example.ini`](config.example.ini) die Vorlage.

Für Stufe 2 und Passwort-Reset müssen die Maildaten stimmen. Bei Gmail oder Microsoft 365 wird meistens ein App-Passwort benötigt.

## 2. Gespeicherte Daten

In SQLite werden E-Mail-Adresse, Passwort-Hash, Zeit der Passwortänderung, letzter erfolgreicher Login, OTP-Schlüssel und zeitlich begrenzte Reset-Token gespeichert.

Das Klartextpasswort wird im Browser mit SHA-256 in einen Client-Schlüssel umgewandelt. Der Server erhält nur diesen Schlüssel und speichert davon zusätzlich einen langsamen Passwort-Hash. Der Schlüssel ist nicht entschlüsselbar.

Sitzungen sind 15 Minuten gültig, E-Mail-Codes 5 Minuten und OTP-Codes 30 Sekunden.

## 3. Python lokal

Voraussetzung: Python 3.11 oder neuer.

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python python_app.py
```

Öffne danach <http://127.0.0.1:5000>.

Wenn PowerShell die Aktivierung blockiert, kann die Anwendung auch direkt gestartet werden:

```powershell
.venv\Scripts\python.exe python_app.py
```

## 4. PythonAnywhere

Lade `python_app.py`, `requirements.txt`, `config.ini` und optional die vorhandene `login.sqlite3` hoch. Installiere die Abhängigkeit:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Lege eine Web-App mit manueller Python-Konfiguration an. In der WSGI-Datei:

```python
import sys
sys.path.insert(0, '/home/DEIN_NAME/Gruber_Login')
from python_app import app as application
```

Trage bei Virtualenv `/home/DEIN_NAME/Gruber_Login/.venv` ein, klicke auf **Reload** und öffne die PythonAnywhere-Adresse. SMTP-Zugangsdaten bleiben ausschließlich in `config.ini` beziehungsweise in der geschützten Serverkopie.

## 5. PHP mit XAMPP

1. Starte Apache im XAMPP Control Panel.
2. Kopiere den gesamten Projektordner nach `C:\xampp\htdocs\login`, damit `config.ini` neben dem Ordner `php` liegt.
3. Aktiviere in `php.ini` `pdo_sqlite` und `sqlite3`.
4. Konfiguriere XAMPP Sendmail einmal für das SMTP-Konto. Die PHP-Anwendung verwendet dafür die native PHP-Funktion `mail()`.
5. Öffne `http://127.0.0.1/login/php/`.

Wenn Apache auf Port 8080 läuft, ändere in `config.ini`:

```ini
[php]
app_url = http://127.0.0.1:8080/login/php
```

Die PHP-Datenbank `php/login.sqlite3` wird beim ersten Aufruf angelegt.

## 6. Testablauf

1. Setze `auth_level = 1` und registriere ein Konto.
2. Teste die direkte Anmeldung.
3. Setze `auth_level = 2`, starte die Anwendung neu und teste den E-Mail-Code.
4. Setze `auth_level = 3`, registriere ein neues Konto und übertrage den angezeigten OTP-Schlüssel in eine Authenticator-App. Beim Login wird danach kein E-Mail-Code mehr verlangt.
5. Teste den Passwort-Reset.

Für echten Betrieb zusätzlich HTTPS, sichere Cookies, Rate-Limiting und eine QR-Code-Einrichtung für OTP verwenden. SMTP-Passwörter niemals veröffentlichen oder in Git einchecken.
