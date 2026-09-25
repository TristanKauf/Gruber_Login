<?php
session_start();
const AUTH_LEVEL = 3; // 1 = Passwort, 2 = E-Mail-Code, 3 = E-Mail-Code + OTP
const LOGIN_WINDOW_MINUTES = 15;
$db = new PDO('sqlite:' . __DIR__ . '/login.sqlite3');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, password_changed_at TEXT NOT NULL, last_login_at TEXT, reset_token_hash TEXT, reset_expires_at INTEGER, totp_secret TEXT NOT NULL)");
function csrf(): string { if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16)); return $_SESSION['csrf']; }
function check_csrf(): void { if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) die('Ungueltige Anfrage'); }
function client_secret(string $password): string { return hash('sha256', $password); }
function h(string $value): string { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); }
function page(string $body): void { echo '<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Secure Login</title><style>body{font:16px system-ui;max-width:540px;margin:3rem auto;padding:0 1rem;background:#f4f6f8;color:#17212b}main{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 8px 30px #0001}label{display:block;margin-top:1rem;font-weight:600}input,button{box-sizing:border-box;width:100%;padding:.7rem;margin-top:.35rem;border:1px solid #bbc5ce;border-radius:6px}button{background:#1769aa;color:white;border:0;margin-top:1.3rem}a{color:#1769aa}.flash{padding:.7rem;background:#fff2cc;border-left:4px solid #d99b00}</style><main>'.$body.'</main></html>'; }
function flash(string $message): void { $_SESSION['flash'] = $message; }
function show_flash(): string { $message = $_SESSION['flash'] ?? ''; unset($_SESSION['flash']); return $message ? '<p class="flash">'.h($message).'</p>' : ''; }
function totp(string $secret): string { $counter = pack('J', intdiv(time(), 30)); $key = base64_decode($secret); $hash = hash_hmac('sha1', $counter, $key, true); $offset = ord($hash[19]) & 15; $number = (unpack('N', substr($hash, $offset, 4))[1] & 0x7fffffff) % 1000000; return str_pad((string)$number, 6, '0', STR_PAD_LEFT); }
function require_login(): void { if (empty($_SESSION['user_id'])) { header('Location: index.php'); exit; } }
?>