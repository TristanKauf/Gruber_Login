<?php
require __DIR__ . '/config.php';
$token = $_POST['token'] ?? $_GET['token'] ?? '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    check_csrf();
    $rows = $db->query('SELECT * FROM users WHERE reset_expires_at > '.time())->fetchAll(PDO::FETCH_ASSOC);
    $user = null;
    foreach ($rows as $row) { if (password_verify($token, $row['reset_token_hash'])) { $user = $row; break; } }
    if ($user && strlen($_POST['password'] ?? '') >= 8) {
        $stmt = $db->prepare('UPDATE users SET password_hash=?,password_changed_at=?,reset_token_hash=NULL,reset_expires_at=NULL WHERE id=?');
        $stmt->execute([password_hash(client_secret($_POST['password']), PASSWORD_DEFAULT), gmdate('c'), $user['id']]);
        flash('Passwort geändert.'); header('Location: index.php'); exit;
    }
    flash('Der Link ist ungültig oder das Passwort zu kurz.');
}
$script = '<script>async function protect(form){const b=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(form.password.value));form.password.value=Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,"0")).join("");return true}</script>';
page('<h2>Neues Passwort</h2><form method="post" onsubmit="return protect(this)"><input type="hidden" name="csrf" value="'.h(csrf()).'"><input type="hidden" name="token" value="'.h($token).'" ><label>Passwort<input type="password" name="password" minlength="8" required></label><button>Speichern</button></form>'.$script);
?>
