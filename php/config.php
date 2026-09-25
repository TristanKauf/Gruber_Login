<?php
/** Shared configuration and security helpers for the PHP application. */
session_start();

$configPath = is_file(__DIR__ . '/../config.ini') ? __DIR__ . '/../config.ini' : __DIR__ . '/config.ini';
$settings = is_file($configPath) ? parse_ini_file($configPath, true, INI_SCANNER_RAW) : [];
$authLevel = (int)($settings['app']['auth_level'] ?? 1);
$mailFrom = (string)($settings['mail']['from'] ?? 'login@example.com');
$appUrl = rtrim((string)($settings['php']['app_url'] ?? 'http://127.0.0.1/login'), '/');

define('AUTH_LEVEL', in_array($authLevel, [1, 2, 3], true) ? $authLevel : 1);
const LOGIN_MINUTES = 15;
const CODE_MINUTES = 5;
const RESET_MINUTES = 15;
define('MAIL_FROM', $mailFrom !== '' ? $mailFrom : 'login@example.com');
define('APP_URL', $appUrl);

$db = new PDO('sqlite:' . __DIR__ . '/login.sqlite3');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->exec('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, password_changed_at TEXT NOT NULL, last_login_at TEXT, totp_secret TEXT NOT NULL, reset_token_hash TEXT, reset_expires_at INTEGER)');

/** Return the session CSRF token. */
function csrf(): string { if (empty($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(32)); } return $_SESSION['csrf']; }

/** Reject a POST request with an invalid CSRF token. */
function check_csrf(): void { if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) { http_response_code(400); exit('Ungueltige Anfrage'); } }

/** Save the global login security level in the shared config.ini file. */
function save_auth_level(int $level): bool { global $configPath; $contents = file_get_contents($configPath); if ($contents === false) { return false; } $updated = preg_replace('/^auth_level\s*=.*$/m', 'auth_level = ' . $level, $contents, 1, $count); return $count === 1 && file_put_contents($configPath, $updated) !== false; }

/** Escape text before inserting it into HTML. */
function h(string $value): string { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); }

/** Return the browser-derived password value. */
function client_secret(string $password): string { return hash('sha256', $password); }

/** Display a one-time message after a redirect. */
function flash(string $message): void { $_SESSION['flash'] = $message; }

/** Render and remove the current one-time message. */
function show_flash(): string { $message = $_SESSION['flash'] ?? ''; unset($_SESSION['flash']); return $message === '' ? '' : '<p class="message">' . h($message) . '</p>'; }

/** Send a real email through the PHP mail transport configured in XAMPP. */
function send_mail(string $recipient, string $subject, string $body): bool { $headers = 'From: ' . MAIL_FROM . "\r\n" . 'Content-Type: text/plain; charset=UTF-8'; return mail($recipient, $subject, $body, $headers); }

/** Render a page with the common styles and security level. */
function page(string $body): void { echo '<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title><style>body{font:16px system-ui;max-width:520px;margin:40px auto;padding:0 16px;background:#f3f5f7}main{background:#fff;padding:28px;border-radius:10px}label{display:block;margin-top:14px;font-weight:600}input,button{width:100%;box-sizing:border-box;padding:10px;margin-top:5px}button{background:#1464a0;color:#fff;border:0;margin-top:20px;cursor:pointer}.message{padding:10px;background:#fff2c7}a{color:#1464a0}.small{color:#5b6570;font-size:.9rem}</style><main><h1>Login</h1><p class="small">Sicherheitsstufe ' . AUTH_LEVEL . ' von 3</p>' . show_flash() . $body . '</main></html>'; }

/** Complete authentication and save the successful-login timestamp. */
function finish_login(int $userId): void { global $db; session_regenerate_id(true); $_SESSION = ['user_id' => $userId, 'authenticated_at' => time(), 'csrf' => $_SESSION['csrf'] ?? bin2hex(random_bytes(32))]; $stmt = $db->prepare('UPDATE users SET last_login_at=? WHERE id=?'); $stmt->execute([gmdate('c'), $userId]); }

/** Require a session that has not exceeded the login time limit. */
function require_login(): void { if (empty($_SESSION['user_id']) || time() - ($_SESSION['authenticated_at'] ?? 0) > LOGIN_MINUTES * 60) { session_destroy(); header('Location: index.php'); exit; } }

/** Generate the current six-digit TOTP value. */
function totp(string $secret): string { $counter = pack('J', intdiv(time(), 30)); $hash = hash_hmac('sha1', $counter, base64_decode($secret), true); $offset = ord($hash[19]) & 15; $number = (unpack('N', substr($hash, $offset, 4))[1] & 0x7fffffff) % 1000000; return str_pad((string)$number, 6, '0', STR_PAD_LEFT); }
?>
