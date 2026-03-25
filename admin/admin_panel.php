<?php
session_start();
include(__DIR__ . "/../config/db.php");

// Check if user is logged in and is admin
if (!isset($_SESSION['user'])) {
    header("Location: ../auth/login.php");
    exit();
}

$stmt = $conn->prepare("SELECT role FROM users WHERE username = ?");
$stmt->bind_param("s", $_SESSION['user']);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

if (!$user || $user['role'] !== 'admin') {
    header("Location: dashboard.php");
    exit();
}
$stmt->close();

$message = '';
$error = '';

// Handle user actions
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['create_user'])) {
        $username = trim($_POST['username']);
        $password = $_POST['password'];
        $role = $_POST['role'];
        
        if (strlen($username) >= 3 && strlen($password) >= 6) {
            $encryption_key = bin2hex(openssl_random_pseudo_bytes(32));
            $hashed_password = password_hash($password, PASSWORD_BCRYPT);
            
            $stmt = $conn->prepare("INSERT INTO users (username, password, encryption_key, role) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("ssss", $username, $hashed_password, $encryption_key, $role);
            
            if ($stmt->execute()) {
                $message = "✅ User created! Encryption Key: $encryption_key";
            } else {
                $error = "Username already exists.";
            }
            $stmt->close();
        } else {
            $error = "Username (min 3) and password (min 6) required.";
        }
    }
    
    if (isset($_POST['delete_user']) && isset($_POST['user_id'])) {
        $user_id = intval($_POST['user_id']);
        if ($user_id != $_SESSION['user_id'] ?? 0) {
            $stmt = $conn->prepare("DELETE FROM users WHERE id = ?");
            $stmt->bind_param("i", $user_id);
            if ($stmt->execute()) {
                $message = "User deleted successfully.";
            } else {
                $error = "Failed to delete user.";
            }
            $stmt->close();
        } else {
            $error = "You cannot delete your own account.";
        }
    }
    
    if (isset($_POST['reset_lockout']) && isset($_POST['user_id'])) {
        $user_id = intval($_POST['user_id']);
        $stmt = $conn->prepare("UPDATE users SET is_locked = FALSE, lockout_until = NULL, failed_attempts = 0 WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            $message = "User lockout reset successfully.";
        }
        $stmt->close();
    }
}

// Get all users
$users = $conn->query("SELECT id, username, role, encryption_key, created_at, is_locked, failed_attempts FROM users ORDER BY id DESC");
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - MOHAZ BANK</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: white; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 2px solid #334155; flex-wrap: wrap; gap: 15px; }
        .card { background: #1e293b; border-radius: 10px; padding: 25px; margin-bottom: 30px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 8px; color: #94a3b8; }
        input, select { width: 100%; padding: 10px; background: #0f172a; border: 1px solid #334155; color: white; border-radius: 5px; }
        button { background: #22c55e; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
        .btn-danger { background: #dc2626; }
        .btn-warning { background: #f59e0b; }
        .nav { display: flex; gap: 15px; flex-wrap: wrap; }
        .nav a { color: #38bdf8; text-decoration: none; padding: 8px 16px; background: #334155; border-radius: 5px; }
        .logout-btn { background: #dc2626 !important; color: white !important; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #334155; }
        th { background: #334155; color: #38bdf8; }
        .message { background: #22c55e; padding: 12px; border-radius: 5px; margin-bottom: 20px; }
        .error { background: #dc2626; padding: 12px; border-radius: 5px; margin-bottom: 20px; }
        .badge-admin { background: #3b82f6; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
        .badge-user { background: #64748b; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
        .badge-locked { background: #dc2626; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
        .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; }
        @media (max-width: 768px) {
            .header { flex-direction: column; text-align: center; }
            th, td { padding: 8px; font-size: 12px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div><h1>👑 Admin Control Panel</h1></div>
            <div class="nav">
                <a href="dashboard.php">📊 Dashboard</a>
                <a href="customers.php">👥 Customers</a>
                <a href="admin_panel.php">👑 Admin Panel</a>
                <a href="../auth/logout.php" class="logout-btn">🚪 Logout</a>
            </div>
        </div>
        
        <?php if ($message): ?><div class="message"><?php echo $message; ?></div><?php endif; ?>
        <?php if ($error): ?><div class="error">❌ <?php echo $error; ?></div><?php endif; ?>
        
        <div class="grid-2">
            <div class="card">
                <h2>➕ Create New User</h2>
                <form method="POST">
                    <div class="form-group">
                        <label>Username (min 3 chars):</label>
                        <input type="text" name="username" required>
                    </div>
                    <div class="form-group">
                        <label>Password (min 6 chars):</label>
                        <input type="password" name="password" required>
                    </div>
                    <div class="form-group">
                        <label>Role:</label>
                        <select name="role">
                            <option value="user">Regular User</option>
                            <option value="admin">Administrator</option>
                        </select>
                    </div>
                    <button type="submit" name="create_user">Create User</button>
                </form>
            </div>
            
            <div class="card">
                <h2>📊 System Statistics</h2>
                <?php
               