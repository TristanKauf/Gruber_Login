<?php
require __DIR__ . '/config.php';
if (empty($_SESSION['pending_user']) || empty($_SESSION['email_verified'])) { header('Location: index.php'); exit; }
$stmt = $db->prepare('SELECT * FROM users WHERE id=?');
$stmt->execute([$_SESSION['pending_user']]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    check_csrf();
    if ($user && hash_equals(totp($user['totp_secret']), $_POST['code'] ?? '')) {
        finish_login((int)$user['id']);
        header('Location: dashboard.php'); exit;
    }
    flash('OTP ist falsch oder abgelaufen.');
}
$token = $user ? h($user['totp_secret']) : 'nicht verfügbar';
page('<h2>OTP Authenticator</h2><p class="small">Auth-Token für deine Authenticator-App:</p><p><strong>'.$token.'</strong></p><form method="post"><input type="hidden" name="csrf" value="'.h(csrf()).'"><label>6-stelliger OTP<input name="code" pattern="[0-9]{6}" required></label><button>Einloggen</button></form>');
?>
