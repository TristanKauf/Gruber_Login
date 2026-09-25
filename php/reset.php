<?php
require __DIR__ . '/config.php';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    check_csrf();
    $email = strtolower(trim($_POST['email'] ?? ''));
    $stmt = $db->prepare('SELECT id FROM users WHERE email=?');
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($user) {
        $token = bin2hex(random_bytes(32));
        $db->prepare('UPDATE users SET reset_token_hash=?,reset_expires_at=? WHERE id=?')->execute([password_hash($token, PASSWORD_DEFAULT), time() + RESET_MINUTES * 60, $user['id']]);
        $link = APP_URL . '/reset-password.php?token=' . urlencode($token);
        if (!send_mail($email, 'Passwort zurücksetzen', "Öffne diesen Link innerhalb von 15 Minuten:\n$link")) {
            $db->prepare('UPDATE users SET reset_token_hash=NULL,reset_expires_at=NULL WHERE id=?')->execute([$user['id']]);
        }
    }
    flash('Wenn die E-Mail existiert, wurde ein Reset-Link versendet.');
}
page('<h2>Passwort zurücksetzen</h2><form method="post"><input type="hidden" name="csrf" value="'.h(csrf()).'"><label>E-Mail<input type="email" name="email" required></label><button>Link anfordern</button></form>');
?>
