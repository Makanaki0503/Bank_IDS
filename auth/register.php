<?php
session_start();
include(__DIR__ . "/../config/db.php");

$error = '';
$success = '';
$encryption_key_display = '';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    
    // Validation
    if (empty($username) || empty($password)) {
        $error = "All fields are required.";
    } elseif (strlen($username) < 3) {
        $error = "Username must be at least 3 characters.";
    } elseif (strlen($password) < 6) {
        $error = "Password must be at least 6 characters.";
    } elseif ($password !== $confirm_password) {
        $error = "Passwords do not match.";
    } else {
        // Create users table if it doesn't exist
        $conn->query("CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE,
            password VARCHAR(255),
            encryption_key VARCHAR(255),
            role VARCHAR(50) DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )");
        
        // Check if username exists
        $check_stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $check_stmt->bind_param("s", $username);
        $check_stmt->execute();
        $check_result = $check_stmt->get_result();
        
        if ($check_result->num_rows > 0) {
            $error = "Username already exists. Please choose another.";
        } else {
            // Generate encryption key
            $encryption_key = bin2hex(openssl_random_pseudo_bytes(32));
            $hashed_password = password_hash($password, PASSWORD_BCRYPT);
            
            $stmt = $conn->prepare("INSERT INTO users (username, password, encryption_key, role) VALUES (?, ?, ?, 'user')");
            $stmt->bind_param("sss", $username, $hashed_password, $encryption_key);
            
            if ($stmt->execute()) {
                $encryption_key_display = $encryption_key;
                $success = "Registration successful!";
            } else {
                $error = "Registration failed: " . $conn->error;
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - MOHAZ BANK IDPS</title>
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
        
        .register-container {
            background: rgba(30, 41, 59, 0.95);
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 450px;
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
            border: 1px solid #334155;
            background: #0f172a;
            color: white;
            border-radius: 8px;
            font-size: 16px;
        }
        
        input:focus {
            outline: none;
            border-color: #38bdf8;
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
        }
        
        button:hover {
            background: #16a34a;
        }
        
        .error {
            background: #dc2626;
            color: white;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        .success {
            background: #22c55e;
            color: white;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        .key-box {
            background: #0f172a;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            border: 1px solid #38bdf8;
        }
        
        .key-box code {
            color: #38bdf8;
            font-size: 12px;
            word-break: break-all;
            display: block;
            margin-top: 10px;
        }
        
        .warning {
            color: #fbbf24;
            font-size: 12px;
            margin-top: 10px;
            text-align: center;
        }
        
        .login-link {
            margin-top: 20px;
            text-align: center;
        }
        
        .login-link a {
            color: #38bdf8;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="register-container">
        <h1>🔐 Create Account</h1>
        <div class="subtitle">Secure Banking with Personal Encryption</div>
        
        <?php if ($error): ?>
            <div class="error">❌ <?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="success">✅ <?php echo $success; ?></div>
            <div class="key-box">
                <strong>🔑 YOUR PERSONAL ENCRYPTION KEY:</strong>
                <code><?php echo $encryption_key_display; ?></code>
            </div>
            <div class="warning">
                ⚠️ IMPORTANT: Save this key! You will need it to view customer data.
            </div>
            <div class="login-link">
                <a href="login.php">→ Proceed to Login</a>
            </div>
        <?php else: ?>
            <form method="POST" action="">
                <div class="form-group">
                    <label for="username">Username (min 3 characters):</label>
                    <input type="text" id="username" name="username" required autocomplete="off">
                </div>
                
                <div class="form-group">
                    <label for="password">Password (min 6 characters):</label>
                    <input type="password" id="password" name="password" required>
                </div>
                
                <div class="form-group">
                    <label for="confirm_password">Confirm Password:</label>
                    <input type="password" id="confirm_password" name="confirm_password" required>
                </div>
                
                <button type="submit">Register</button>
            </form>
            <div class="login-link">
                Already have an account? <a href="login.php">Login here</a>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>