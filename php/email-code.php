<?php
require __DIR__ . '/config.php';
if (empty($_SESSION['pending_user'])) { header('Location: index.php'); exit; }
if (AUTH_LEVEL !== 2) { header('Location: index.php'); exit; }
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    check_csrf();
    $valid = time() < ($_SESSION['email_code_expires'] ?? 0) && password_verify($_POST['code'] ?? '', $_SESSION['email_code_hash'] ?? '');
    if (!$valid) {
        flash('Der Code ist falsch oder abgelaufen.');
    } elseif (AUTH_LEVEL === 2) {
        finish_login((int)$_SESSION['pending_user']);
        header('Location: dashboard.php'); exit;
    }
}
page('<h2>E-Mail bestätigen</h2><form method="post"><input type="hidden" name="csrf" value="'.h(csrf()).'"><label>6-stelliger Code<input name="code" pattern="[0-9]{6}" required></label><button>Prüfen</button></form>');
?>
