<?php
// Include intrusion detection FIRST
include(__DIR__ . "/../security/detect.php");

session_start();
include(__DIR__ . "/../config/db.php");

// Initialize variables
$error = '';
$success_message = '';
$locked = false;
$remaining_attempts = 5;

// Check for logout success message
if (isset($_GET['logout']) && $_GET['logout'] == 'success') {
    $success_message = "✅ You have been successfully logged out.";
}

// Check if user is already logged in
if (isset($_SESSION['user'])) {
    header("Location: ../admin/dashboard.php");
    exit();
}

// Get IP address for logging
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

// Create necessary tables if they don't exist
try {
    // Users table
    $conn->query("CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        encryption_key VARCHAR(255),
        role VARCHAR(50) DEFAULT 'user',
        is_locked BOOLEAN DEFAULT FALSE,
        lockout_until TIMESTAMP NULL,
        failed_attempts INT DEFAULT 0,
        last_failed_login TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )");
    
    // Failed logins table
    $conn->query("CREATE TABLE IF NOT EXISTS failed_logins (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ip_address VARCHAR(45) NOT NULL,
        username VARCHAR(50),
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )");
    
    // Intrusion logs table
    $conn->query("CREATE TABLE IF NOT EXISTS intrusion_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ip_address VARCHAR(45),
        activity TEXT,
        threat_level VARCHAR(20),
        status VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )");
    
    // Blocked IPs table
    $conn->query("CREATE TABLE IF NOT EXISTS blocked_ips (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ip_address VARCHAR(45) UNIQUE,
        expires_at TIMESTAMP NULL,
        reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )");
    
    // Add missing columns if needed
    $result = $conn->query("SHOW COLUMNS FROM users LIKE 'encryption_key'");
    if ($result && $result->num_rows == 0) {
        $conn->query("ALTER TABLE users ADD COLUMN encryption_key VARCHAR(255) AFTER password");
    }
    
    $result = $conn->query("SHOW COLUMNS FROM users LIKE 'role'");
    if ($result && $result->num_rows == 0) {
        $conn->query("ALTER TABLE users ADD COLUMN role VARCHAR(50) DEFAULT 'user' AFTER encryption_key");
    }
    
    $result = $conn->query("SHOW COLUMNS FROM users LIKE 'is_locked'");
    if ($result && $result->num_rows == 0) {
        $conn->query("ALTER TABLE users ADD COLUMN is_locked BOOLEAN DEFAULT FALSE");
    }
    
    $result = $conn->query("SHOW COLUMNS FROM users LIKE 'lockout_until'");
    if ($result && $result->num_rows == 0) {
        $conn->query("ALTER TABLE users ADD COLUMN lockout_until TIMESTAMP NULL");
    }
    
    $result = $conn->query("SHOW COLUMNS FROM users LIKE 'failed_attempts'");
    if ($result && $result->num_rows == 0) {
        $conn->query("ALTER TABLE users ADD COLUMN failed_attempts INT DEFAULT 0");
    }
    
    $result = $conn->query("SHOW COLUMNS FROM users LIKE 'last_failed_login'");
    if ($result && $result->num_rows == 0) {
        $conn->query("ALTER TABLE users ADD COLUMN last_failed_login TIMESTAMP NULL");
    }
    
} catch (Exception $e) {
    error_log("Table creation error: " . $e->getMessage());
}

// Check if IP is blocked
$blocked = false;
$block_stmt = $conn->prepare("SELECT id, reason, expires_at FROM blocked_ips WHERE ip_address = ? AND (expires_at IS NULL OR expires_at > NOW())");
if ($block_stmt) {
    $block_stmt->bind_param("s", $ip);
    $block_stmt->execute();
    $block_result = $block_stmt->get_result();
    if ($block_result && $block_result->num_rows > 0) {
        $blocked = true;
        $block_info = $block_result->fetch_assoc();
        $error = "Your IP address has been blocked. " . ($block_info['expires_at'] ? "Block expires: " . date('Y-m-d H:i:s', strtotime($block_info['expires_at'])) : "Permanent block");
    }
    $block_stmt->close();
}

// Handle login form submission
if ($_SERVER["REQUEST_METHOD"] == "POST" && !$blocked) {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    
    if (empty($username) || empty($password)) {
        $error = "Username and password are required.";
    } else {
        try {
            // Check if user is locked out
            $lock_stmt = $conn->prepare("SELECT is_locked, lockout_until, failed_attempts FROM users WHERE username = ?");
            $lock_stmt->bind_param("s", $username);
            $lock_stmt->execute();
            $lock_result = $lock_stmt->get_result();
            
            if ($lock_result && $user_lock = $lock_result->fetch_assoc()) {
                if ($user_lock['is_locked'] && strtotime($user_lock['lockout_until']) > time()) {
                    $error = "Account is temporarily locked. Please try again after " . date('H:i:s', strtotime($user_lock['lockout_until'])) . ".";
                    $locked = true;
                } else if ($user_lock['is_locked']) {
                    // Reset lockout if expired
                    $reset_stmt = $conn->prepare("UPDATE users SET is_locked = FALSE, lockout_until = NULL WHERE username = ?");
                    $reset_stmt->bind_param("s", $username);
                    $reset_stmt->execute();
                    $reset_stmt->close();
                }
            }
            $lock_stmt->close();
            
            if (!$locked) {
                // Prepare and execute query
                $stmt = $conn->prepare("SELECT id, username, password, role, encryption_key, failed_attempts FROM users WHERE username = ?");
                $stmt->bind_param("s", $username);
                $stmt->execute();
                $result = $stmt->get_result();
                
                if ($user = $result->fetch_assoc()) {
                    // Verify password
                    if (password_verify($password, $user['password'])) {
                        // Successful login - reset failed attempts
                        $reset_stmt = $conn->prepare("UPDATE users SET failed_attempts = 0, last_failed_login = NULL WHERE id = ?");
                        $reset_stmt->bind_param("i", $user['id']);
                        $reset_stmt->execute();
                        $reset_stmt->close();
                        
                        // Generate encryption key if missing
                        if (empty($user['encryption_key'])) {
                            $new_key = bin2hex(openssl_random_pseudo_bytes(32));
                            $update_stmt = $conn->prepare("UPDATE users SET encryption_key = ? WHERE id = ?");
                            $update_stmt->bind_param("si", $new_key, $user['id']);
                            $update_stmt->execute();
                            $user['encryption_key'] = $new_key;
                        }
                        
                        // Regenerate session ID for security
                        session_regenerate_id(true);
                        
                        // Set session variables
                        $_SESSION['user'] = $user['username'];
                        $_SESSION['user_id'] = $user['id'];
                        $_SESSION['role'] = $user['role'];
                        $_SESSION['encryption_key'] = $user['encryption_key'];
                        $_SESSION['login_time'] = time();
                        $_SESSION['ip_address'] = $ip;
                        
                        // Log successful login
                        $log_stmt = $conn->prepare("INSERT INTO intrusion_logs (ip_address, activity, threat_level, status) VALUES (?, ?, ?, ?)");
                        if ($log_stmt) {
                            $activity = "Successful login: $username";
                            $threat_level = "Low";
                            $status = "Success";
                            $log_stmt->bind_param("ssss", $ip, $activity, $threat_level, $status);
                            $log_stmt->execute();
                            $log_stmt->close();
                        }
                        
                        // Redirect to dashboard
                        header("Location: ../admin/dashboard.php");
                        exit();
                    } else {
                        // Failed login
                        $failed_attempts = $user['failed_attempts'] + 1;
                        $update_stmt = $conn->prepare("UPDATE users SET failed_attempts = ?, last_failed_login = NOW() WHERE id = ?");
                        $update_stmt->bind_param("ii", $failed_attempts, $user['id']);
                        $update_stmt->execute();
                        $update_stmt->close();
                        
                        // Log failed login
                        $log_stmt = $conn->prepare("INSERT INTO failed_logins (ip_address, username, user_agent) VALUES (?, ?, ?)");
                        if ($log_stmt) {
                            $log_stmt->bind_param("sss", $ip, $username, $user_agent);
                            $log_stmt->execute();
                            $log_stmt->close();
                        }
                        
                        // Log to intrusion logs
                        $log_stmt = $conn->prepare("INSERT INTO intrusion_logs (ip_address, activity, threat_level, status) VALUES (?, ?, ?, ?)");
                        if ($log_stmt) {
                            $activity = "Failed login attempt for user: $username (Attempt #$failed_attempts)";
                            $threat_level = $failed_attempts >= 3 ? "Medium" : "Low";
                            $status = "Failed";
                            $log_stmt->bind_param("ssss", $ip, $activity, $threat_level, $status);
                            $log_stmt->execute();
                            $log_stmt->close();
                        }
                        
                        // Lock account after 5 failed attempts
                        if ($failed_attempts >= 5) {
                            $lockout_until = date('Y-m-d H:i:s', strtotime('+15 minutes'));
                            $lock_stmt = $conn->prepare("UPDATE users SET is_locked = TRUE, lockout_until = ? WHERE id = ?");
                            $lock_stmt->bind_param("si", $lockout_until, $user['id']);
                            $lock_stmt->execute();
                            $lock_stmt->close();
                            
                            $error = "Account locked due to too many failed attempts. Please try again after 15 minutes.";
                            $locked = true;
                        } else {
                            $remaining_attempts = 5 - $failed_attempts;
                            $error = "Invalid password. You have $remaining_attempts attempt(s) remaining before account lockout.";
                        }
                    }
                } else {
                    // User not found - log failed attempt
                    $log_stmt = $conn->prepare("INSERT INTO failed_logins (ip_address, username, user_agent) VALUES (?, ?, ?)");
                    if ($log_stmt) {
                        $log_stmt->bind_param("sss", $ip, $username, $user_agent);
                        $log_stmt->execute();
                        $log_stmt->close();
                    }
                    
                    $error = "Invalid username or password.";
                }
                $stmt->close();
            }
        } catch (Exception $e) {
            error_log("Login error: " . $e->getMessage());
            $error = "System error. Please try again later.";
        }
    }
}

// Generate CSRF token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - MOHAZ BANK IDPS</title>
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
        
        .login-container {
            background: rgba(30, 41, 59, 0.95);
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 400px;
            backdrop-filter: blur(10px);
            animation: fadeIn 0.5s ease-in;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .logo {
            text-align: center;
            font-size: 48px;
            margin-bottom: 20px;
        }
        
        h1 {
            color: #38bdf8;
            text-align: center;
            margin-bottom: 10px;
            font-size: 28px;
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
            transition: all 0.3s;
        }
        
        button:hover:not(:disabled) {
            background: #16a34a;
            transform: translateY(-1px);
        }
        
        button:disabled {
            background: #64748b;
            cursor: not-allowed;
        }
        
        .error {
            background: #dc2626;
            color: white;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
            animation: shake 0.5s;
        }
        
        .success {
            background: #22c55e;
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
        
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-5px); }
            75% { transform: translateX(5px); }
        }
        
        .register-link {
            margin-top: 20px;
            text-align: center;
        }
        
        .register-link a {
            color: #38bdf8;
            text-decoration: none;
            transition: color 0.3s;
        }
        
        .register-link a:hover {
            color: #60a5fa;
            text-decoration: underline;
        }
        
        .security-badge {
            text-align: center;
            margin-top: 20px;
            font-size: 12px;
            color: #64748b;
        }
        
        .security-badge span {
            margin: 0 5px;
        }
        
        .attempts-warning {
            background: #fbbf24;
            color: #0f172a;
            padding: 8px;
            border-radius: 5px;
            margin-top: 10px;
            text-align: center;
            font-size: 12px;
        }
        
        .ip-info {
            text-align: center;
            font-size: 10px;
            color: #475569;
            margin-top: 15px;
        }
        
        @media (max-width: 480px) {
            .login-container {
                padding: 30px 20px;
            }
            
            h1 {
                font-size: 24px;
            }
            
            input, button {
                font-size: 14px;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">🔐</div>
        <h1>MOHAZ BANK</h1>
        <div class="subtitle">Intrusion Detection & Prevention System</div>
        
        <?php if ($success_message): ?>
            <div class="success"><?php echo htmlspecialchars($success_message); ?></div>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="error">❌ <?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <?php if ($remaining_attempts <= 2 && $remaining_attempts > 0 && !$locked && !$blocked): ?>
            <div class="warning">
                ⚠️ Warning: You have <?php echo $remaining_attempts; ?> login attempt(s) remaining.
            </div>
        <?php endif; ?>
        
        <?php if ($blocked): ?>
            <div class="error">
                🚫 Your IP address has been blocked due to suspicious activity.
            </div>
        <?php endif; ?>
        
        <?php if (!$blocked && !$locked): ?>
            <form method="POST" action="" id="loginForm">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required autocomplete="off" placeholder="Enter your username">
                </div>
                
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required placeholder="Enter your password">
                </div>
                
                <button type="submit" id="loginBtn">Login</button>
            </form>
        <?php elseif ($locked && !$blocked): ?>
            <div class="warning">
                🔒 Account temporarily locked. Please try again later.
            </div>
        <?php endif; ?>
        
        <div class="register-link">
            Don't have an account? <a href="register.php">Register here</a>
        </div>
        
        <div class="security-badge">
            <span>🔒 AES-256 Encrypted</span> |
            <span>🛡️ IDPS Active</span> |
            <span>🔑 Personal Keys</span> |
            <span>🚫 Brute Force Protection</span>
        </div>
        
        <div class="ip-info">
            Your IP: <?php echo htmlspecialchars($ip); ?>
        </div>
    </div>
    
    <script>
        // Disable login button after click to prevent multiple submissions
        document.getElementById('loginForm')?.addEventListener('submit', function(e) {
            const btn = document.getElementById('loginBtn');
            if (btn) {
                btn.disabled = true;
                btn.textContent = 'Logging in...';
            }
        });
        
        // Add enter key support
        document.getElementById('password')?.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                document.getElementById('loginForm')?.submit();
            }
        });
        
        // Show remaining attempts warning
        <?php if ($remaining_attempts <= 2 && $remaining_attempts > 0): ?>
        console.log('Remaining attempts: <?php echo $remaining_attempts; ?>');
        <?php endif; ?>
    </script>
</body>
</html>