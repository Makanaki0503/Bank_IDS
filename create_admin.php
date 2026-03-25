<?php
/**
 * Admin Account Creator - MOHAZ BANK IDPS
 * This script creates an administrator account
 */

// Start session for admin check
session_start();

// Include database connection
include("config/db.php");

// Check if admin already exists
$admin_exists = false;
$result = $conn->query("SELECT COUNT(*) as count FROM users WHERE role = 'admin'");
if ($result && $row = $result->fetch_assoc()) {
    $admin_exists = ($row['count'] > 0);
}

$message = '';
$error = '';

// Process form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    
    // Validate input
    if (empty($username) || empty($password)) {
        $error = "Username and password are required.";
    } elseif (strlen($username) < 3) {
        $error = "Username must be at least 3 characters.";
    } elseif (strlen($password) < 6) {
        $error = "Password must be at least 6 characters.";
    } elseif ($password !== $confirm_password) {
        $error = "Passwords do not match.";
    } else {
        // Check if username already exists
        $check = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $check->bind_param("s", $username);
        $check->execute();
        $check_result = $check->get_result();
        
        if ($check_result->num_rows > 0) {
            $error = "Username already exists. Please choose another.";
        } else {
            // Generate encryption key
            $encryption_key = bin2hex(openssl_random_pseudo_bytes(32));
            $hashed_password = password_hash($password, PASSWORD_BCRYPT);
            $role = 'admin';
            
            $stmt = $conn->prepare("INSERT INTO users (username, password, encryption_key, role) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("ssss", $username, $hashed_password, $encryption_key, $role);
            
            if ($stmt->execute()) {
                $message = "✅ Admin user created successfully!";
                $show_key = $encryption_key;
            } else {
                $error = "Failed to create admin: " . $conn->error;
            }
            $stmt->close();
        }
        $check->close();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Admin - MOHAZ BANK IDPS</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        
        .container {
            max-width: 500px;
            width: 100%;
            background: #1e293b;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.3);
        }
        
        h1 {
            color: #38bdf8;
            text-align: center;
            margin-bottom: 10px;
        }
        
        .subtitle {
            text-align: center;
            color: #94a3b8;
            margin-bottom: 30px;
            font-size: 14px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #cbd5e1;
            font-weight: 500;
        }
        
        input {
            width: 100%;
            padding: 12px;
            background: #0f172a;
            border: 1px solid #334155;
            color: white;
            border-radius: 8px;
            font-size: 14px;
            transition: all 0.3s;
        }
        
        input:focus {
            outline: none;
            border-color: #38bdf8;
            box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.2);
        }
        
        button {
            width: 100%;
            padding: 12px;
            background: #22c55e;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: background 0.3s;
        }
        
        button:hover {
            background: #16a34a;
        }
        
        .message {
            background: #22c55e;
            color: white;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .error {
            background: #dc2626;
            color: white;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .warning {
            background: #fbbf24;
            color: #0f172a;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .key-box {
            background: #0f172a;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            border: 1px solid #38bdf8;
            word-break: break-all;
        }
        
        .key-box code {
            color: #38bdf8;
            font-family: monospace;
            font-size: 12px;
        }
        
        .login-link {
            text-align: center;
            margin-top: 20px;
        }
        
        .login-link a {
            color: #38bdf8;
            text-decoration: none;
        }
        
        .login-link a:hover {
            text-decoration: underline;
        }
        
        .admin-warning {
            background: #dc2626;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            text-align: center;
            font-size: 14px;
        }
        
        hr {
            border-color: #334155;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 MOHAZ BANK</h1>
        <div class="subtitle">Create Administrator Account</div>
        
        <?php if ($admin_exists && !isset($show_key)): ?>
            <div class="warning">
                ⚠️ An admin account already exists!<br>
                You can still create additional admin accounts.
            </div>
        <?php endif; ?>
        
        <?php if ($message): ?>
            <div class="message"><?php echo $message; ?></div>
            <?php if (isset($show_key)): ?>
                <div class="key-box">
                    <strong>🔑 YOUR ENCRYPTION KEY:</strong><br>
                    <code><?php echo $show_key; ?></code>
                </div>
                <div class="warning">
                    ⚠️ IMPORTANT: Save this encryption key! You will need it to decrypt customer data.
                </div>
                <div class="login-link">
                    <a href="auth/login.php">→ Click here to login</a>
                </div>
            <?php endif; ?>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="error">❌ <?php echo $error; ?></div>
        <?php endif; ?>
        
        <?php if (!isset($show_key)): ?>
            <form method="POST" action="">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required autocomplete="off" placeholder="Enter admin username">
                </div>
                
                <div class="form-group">
                    <label for="password">Password (min 6 characters):</label>
                    <input type="password" id="password" name="password" required placeholder="Enter strong password">
                </div>
                
                <div class="form-group">
                    <label for="confirm_password">Confirm Password:</label>
                    <input type="password" id="confirm_password" name="confirm_password" required placeholder="Confirm password">
                </div>
                
                <button type="submit">Create Administrator Account</button>
            </form>
            
            <hr>
            
            <div class="login-link">
                <a href="auth/login.php">← Back to Login</a> |
                <a href="auth/register.php">Register Regular User</a>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>