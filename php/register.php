<?php
require __DIR__ . '/config.php';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    check_csrf();
    $email = strtolower(trim($_POST['email'] ?? ''));
    $password = $_POST['password'] ?? '';
    if (strlen($password) < 8) {
        flash('Das Passwort muss mindestens acht Zeichen enthalten.');
    } else {
        $secret = base64_encode(random_bytes(20));
        try {
            $stmt = $db->prepare('INSERT INTO users(email,password_hash,password_changed_at,totp_secret) VALUES(?,?,?,?)');
            $stmt->execute([$email, password_hash(client_secret($password), PASSWORD_DEFAULT), gmdate('c'), $secret]);
            flash(AUTH_LEVEL === 3 ? 'Konto erstellt. TOTP-Schlüssel für deine Authenticator-App: '.$secret : 'Konto erstellt.');
            header('Location: index.php'); exit;
        } catch (PDOException $error) {
            flash('Diese E-Mail ist bereits registriert.');
        }
    }
}
$script = '<script>async function protect(form){const b=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(form.password.value));form.password.value=Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,"0")).join("");return true}</script>';
page('<h2>Konto anlegen</h2><form method="post" onsubmit="return protect(this)"><input type="hidden" name="csrf" value="'.h(csrf()).'"><label>E-Mail<input type="email" name="email" required></label><label>Passwort<input type="password" name="password" minlength="8" required></label><button>Registrieren</button></form>'.$script.'<p><a href="index.php">Zur Anmeldung</a></p>');
?>
