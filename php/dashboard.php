<?php
require __DIR__ . '/config.php';
require_login();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	check_csrf();
	$level = (int)($_POST['auth_level'] ?? 0);
	if (in_array($level, [1, 2, 3], true) && save_auth_level($level)) {
		flash('Sicherheitsstufe '.$level.' ist aktiv.');
	} else {
		flash('Die Sicherheitsstufe konnte nicht gespeichert werden.');
	}
	header('Location: dashboard.php'); exit;
}
$stmt = $db->prepare('SELECT email,last_login_at FROM users WHERE id=?');
$stmt->execute([$_SESSION['user_id']]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);
$options = '<option value="1"'.(AUTH_LEVEL === 1 ? ' selected' : '').'>1: E-Mail und Passwort</option><option value="2"'.(AUTH_LEVEL === 2 ? ' selected' : '').'>2: zusätzlich E-Mail-Code</option><option value="3"'.(AUTH_LEVEL === 3 ? ' selected' : '').'>3: zusätzlich OTP-Authenticator</option>';
page('<h2>Angemeldet</h2><p>'.h($user['email']).'</p><p class="small">Letzter Login: '.h($user['last_login_at']).'</p><h2>Sicherheitsstufe</h2><form method="post"><input type="hidden" name="csrf" value="'.h(csrf()).'"><select name="auth_level">'.$options.'</select><button type="submit">Sicherheitsstufe speichern</button></form><p><a href="logout.php">Abmelden</a></p>');
?>
