<?php
session_start();

if (isset($_SESSION["user_id"])) {
    header("Location: index.php");
    exit();
}

require_once "includes/config.php";
require_once "includes/functions.php";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = $_POST["username"] ?? "";
    $email = $_POST["email"] ?? "";
    $password = $_POST["password"] ?? "";
    $confirm_password = $_POST["confirm_password"] ?? "";

    if (
        empty($username) ||
        empty($email) ||
        empty($password) ||
        empty($confirm_password)
    ) {
        // Handle error
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        // Handle error
    } elseif ($password !== $confirm_password) {
        // Handle error
    } elseif (strlen($password) < 6) {
        // Handle error
    } else {
        $conn = getDbConnection();

        $stmt = $conn->prepare(
            "SELECT id FROM users WHERE username = ? OR email = ?"
        );
        $stmt->bind_param("ss", $username, $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            // Handle error
        } else {
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);

            $stmt = $conn->prepare(
                "INSERT INTO users (username, email, password, created_at) VALUES (?, ?, ?, NOW())"
            );
            $stmt->bind_param("sss", $username, $email, $hashed_password);

            if ($stmt->execute()) {
                $user_data = [
                    'username' => $username,
                    'email' => $email,
                    'created_at' => date('Y-m-d H:i:s')
                ];
                file_put_contents('login.json', json_encode($user_data, JSON_PRETTY_PRINT));
            }
        }

        $stmt->close();
        $conn->close();
    }
}
?>
