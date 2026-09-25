<?php
require __DIR__ . '/config.php';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    check_csrf();
    $email = strtolower(trim($_POST['email'] ?? ''));
    $stmt = $db->prepare('SELECT * FROM users WHERE email=?');
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$user || !password_verify(client_secret($_POST['password'] ?? ''), $user['password_hash'])) {
        flash('E-Mail oder Passwort ist falsch.');
        header('Location: index.php'); exit;
    }
    if (AUTH_LEVEL === 1) {
        finish_login((int)$user['id']);
        header('Location: dashboard.php'); exit;
    }
    $_SESSION['pending_user'] = (int)$user['id'];
    if (AUTH_LEVEL === 3) {
        $_SESSION['email_verified'] = true;
        header('Location: otp.php'); exit;
    }
    $code = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    $_SESSION['email_code_hash'] = password_hash($code, PASSWORD_DEFAULT);
    $_SESSION['email_code_expires'] = time() + CODE_MINUTES * 60;
    if (!send_mail($email, 'Dein Login-Code', "Dein Login-Code lautet: $code\nEr ist fünf Minuten gültig.")) {
        unset($_SESSION['pending_user'], $_SESSION['email_code_hash'], $_SESSION['email_code_expires']);
        flash('Die E-Mail konnte nicht versendet werden. XAMPP-Mail konfigurieren.');
        header('Location: index.php'); exit;
    }
    header('Location: email-code.php'); exit;
}
$script = '<script>async function protect(form){const b=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(form.password.value));form.password.value=Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,"0")).join("");return true}</script>';
page('<form method="post" onsubmit="return protect(this)"><input type="hidden" name="csrf" value="'.h(csrf()).'"><label>E-Mail<input type="email" name="email" required></label><label>Passwort<input type="password" name="password" required></label><button>Anmelden</button></form>'.$script.'<p><a href="register.php">Konto anlegen</a> | <a href="reset.php">Passwort vergessen?</a></p>');
?>
