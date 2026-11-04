<?php
session_start();
require_once "config.php";

$errors = [];
$name = "";
$email = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $name = trim($_POST["name"] ?? "");
    $email = trim($_POST["email"] ?? "");
    $password = $_POST["password"] ?? "";
    $confirm = $_POST["confirm_password"] ?? "";

    if ($name === "") $errors[] = "Name is required.";
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = "Enter a valid email address.";
    if (strlen($password) < 8) $errors[] = "Password must be at least 8 characters.";
    if (!preg_match('/\d/', $password)) $errors[] = "Password must include at least one number.";
    if ($password !== $confirm) $errors[] = "Passwords do not match.";

    if (!$errors) {
        $check = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $check->bind_param("s", $email);
        $check->execute();

        if ($check->get_result()->fetch_assoc()) {
            $errors[] = "That email address is already registered.";
        } else {
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $insert = $conn->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
            $insert->bind_param("sss", $name, $email, $hash);
            $insert->execute();

            $_SESSION["flash"] = "Registration successful. You can now sign in.";
            header("Location: login.php");
            exit;
        }
    }
}
function e($value) { return htmlspecialchars($value, ENT_QUOTES, "UTF-8"); }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BPC Scholarship Portal | Register</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
<main class="auth-card">
    <div class="auth-brand">
        <img src="bpc-logo.jpg" alt="Bulacan Polytechnic College logo">
        <span>BPC Scholarship Portal</span>
    </div>
    <h1>Create an account</h1>
    <p class="subtitle">Create an account to get started.</p>

    <?php if ($errors): ?>
        <div class="message error">
            <?php foreach ($errors as $error): ?><p><?= e($error) ?></p><?php endforeach; ?>
        </div>
    <?php endif; ?>

    <form method="POST" action="register.php">
        <label for="name">Full name</label>
        <input id="name" name="name" type="text" value="<?= e($name) ?>" autocomplete="name" required>

        <label for="email">Email address</label>
        <input id="email" name="email" type="email" value="<?= e($email) ?>" autocomplete="email" required>

        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="new-password" minlength="8" pattern="(?=.*\d).{8,}" title="Use at least 8 characters and include a number." required>

        <label for="confirm_password">Confirm password</label>
        <input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" minlength="8" required>

        <button type="submit">Register</button>
    </form>
    <p class="switch">Already have an account? <a href="login.php">Sign in</a></p>
</main>
</body>
</html>