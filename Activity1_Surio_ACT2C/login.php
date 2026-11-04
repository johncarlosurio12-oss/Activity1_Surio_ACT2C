<?php
session_start();
require_once "config.php";

$error = "";
$success = $_SESSION["flash"] ?? "";
unset($_SESSION["flash"]);

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $email = trim($_POST["email"] ?? "");
    $password = $_POST["password"] ?? "";

    $stmt = $conn->prepare("SELECT id, name, email, password FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();

    if ($user && password_verify($password, $user["password"])) {
        session_regenerate_id(true);
        $_SESSION["user_id"] = $user["id"];
        $_SESSION["user_name"] = $user["name"];
        $success = "Welcome back, " . htmlspecialchars($user["name"], ENT_QUOTES, "UTF-8") . "! You are signed in.";
    } else {
        $error = "Incorrect email or password.";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BPC Scholarship Portal | Sign in</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
<main class="auth-card">
    <div class="auth-brand">
        <img src="bpc-logo.jpg" alt="Bulacan Polytechnic College logo">
        <span>BPC Scholarship Portal</span>
    </div>
    <h1>Welcome back</h1>
    <p class="subtitle">Sign in to access your scholarship account.</p>

    <?php if ($success): ?>
        <div class="message success"><?= $success ?></div>
    <?php endif; ?>
    <?php if ($error): ?>
        <div class="message error"><?= htmlspecialchars($error, ENT_QUOTES, "UTF-8") ?></div>
    <?php endif; ?>

    <form method="POST" action="login.php">
        <label for="email">Email address</label>
        <input id="email" name="email" type="email" autocomplete="email" required>

        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>

        <button type="submit">Sign in</button>
    </form>
    <p class="switch">Don't have an account? <a href="register.php">Register</a></p>
</main>
</body>
</html>
