<?php
session_start();
include(__DIR__ . "/../config/db.php");
include(__DIR__ . "/../includes/check_role.php");

// Require user to be logged in
requireLogin();

$message = '';
$error = '';
$decrypted_customers = [];
$key_required = true;
$is_admin = isAdmin();
$username = getUsername();
$user_ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

// Get user's encryption key from database
$stmt = $conn->prepare("SELECT encryption_key FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();
$user_key = $user['encryption_key'] ?? '';
$stmt->close();

// Create customers table with all required columns
$conn->query("CREATE TABLE IF NOT EXISTS customers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    customer_id VARCHAR(50) UNIQUE,
    encrypted_name TEXT,
    encrypted_email TEXT,
    encrypted_phone TEXT,
    encrypted_account_number TEXT,
    encrypted_balance TEXT,
    iv VARCHAR(255),
    created_by VARCHAR(50),
    user_key VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)");

// Add user_key column if missing
$result = $conn->query("SHOW COLUMNS FROM customers LIKE 'user_key'");
if ($result && $result->num_rows == 0) {
    $conn->query("ALTER TABLE customers ADD COLUMN user_key VARCHAR(255)");
}

// ============================================
// HANDLE ADD CUSTOMER (Both Admin & Regular User)
// ============================================
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['add_customer'])) {
    $provided_key = trim($_POST['encryption_key'] ?? '');
    
    if (empty($provided_key)) {
        $error = "Encryption key is required!";
    } elseif ($provided_key !== $user_key) {
        $error = "Invalid encryption key! Use your personal encryption key from dashboard.";
    } else {
        $name = trim($_POST['name'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $phone = trim($_POST['phone'] ?? '');
        $account_number = trim($_POST['account_number'] ?? '');
        $balance = trim($_POST['balance'] ?? '');
        
        if (empty($name) || empty($email) || empty($phone) || empty($account_number)) {
            $error = "All fields are required.";
        } else {
            $customer_id = 'CUST' . time() . rand(100, 999);
            
            try {
                // Encrypt each field with the user's key
                $encrypted_name = $encryption->encrypt($name, $user_key);
                $encrypted_email = $encryption->encrypt($email, $user_key);
                $encrypted_phone = $encryption->encrypt($phone, $user_key);
                $encrypted_account = $encryption->encrypt($account_number, $user_key);
                $encrypted_balance = $encryption->encrypt($balance, $user_key);
                
                $enc_name = $encrypted_name['data'];
                $enc_email = $encrypted_email['data'];
                $enc_phone = $encrypted_phone['data'];
                $enc_account = $encrypted_account['data'];
                $enc_balance = $encrypted_balance['data'];
                $iv = $encrypted_name['iv'];
                
                $stmt = $conn->prepare("INSERT INTO customers (customer_id, encrypted_name, encrypted_email, encrypted_phone, encrypted_account_number, encrypted_balance, iv, created_by, user_key) 
                                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
                $stmt->bind_param("sssssssss", 
                    $customer_id,
                    $enc_name,
                    $enc_email,
                    $enc_phone,
                    $enc_account,
                    $enc_balance,
                    $iv,
                    $username,
                    $user_key
                );
                
                if ($stmt->execute()) {
                    $message = "✅ Customer added successfully! ID: $customer_id";
                    
                    // Log the action
                    $log_stmt = $conn->prepare("INSERT INTO intrusion_logs (ip_address, activity, threat_level, status) VALUES (?, ?, ?, ?)");
                    $activity = "User $username added customer: $customer_id";
                    $threat_level = "Low";
                    $status = "Success";
                    $log_stmt->bind_param("ssss", $user_ip, $activity, $threat_level, $status);
                    $log_stmt->execute();
                    $log_stmt->close();
                } else {
                    $error = "Failed to add customer: " . $conn->error;
                }
                $stmt->close();
            } catch (Exception $e) {
                $error = "Encryption error: " . $e->getMessage();
            }
        }
    }
}

// ============================================
// HANDLE EDIT CUSTOMER
// ============================================
if (isset($_POST['edit_customer']) && isset($_POST['customer_id'])) {
    $customer_id = $_POST['customer_id'];
    $provided_key = trim($_POST['encryption_key'] ?? '');
    
    // First, verify ownership
    $check_stmt = $conn->prepare("SELECT created_by, user_key FROM customers WHERE customer_id = ?");
    $check_stmt->bind_param("s", $customer_id);
    $check_stmt->execute();
    $check_result = $check_stmt->get_result();
    $customer_data = $check_result->fetch_assoc();
    $check_stmt->close();
    
    if (!$customer_data) {
        $error = "Customer not found.";
    } elseif (!$is_admin && $customer_data['created_by'] !== $username) {
        $error = "You can only edit customers you created.";
    } elseif ($provided_key !== $user_key) {
        $error = "Invalid encryption key!";
    } else {
        $name = trim($_POST['name'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $phone = trim($_POST['phone'] ?? '');
        $account_number = trim($_POST['account_number'] ?? '');
        $balance = trim($_POST['balance'] ?? '');
        
        if (empty($name) || empty($email) || empty($phone) || empty($account_number)) {
            $error = "All fields are required.";
        } else {
            try {
                // Re-encrypt with user's key
                $encrypted_name = $encryption->encrypt($name, $user_key);
                $encrypted_email = $encryption->encrypt($email, $user_key);
                $encrypted_phone = $encryption->encrypt($phone, $user_key);
                $encrypted_account = $encryption->encrypt($account_number, $user_key);
                $encrypted_balance = $encryption->encrypt($balance, $user_key);
                
                $enc_name = $encrypted_name['data'];
                $enc_email = $encrypted_email['data'];
                $enc_phone = $encrypted_phone['data'];
                $enc_account = $encrypted_account['data'];
                $enc_balance = $encrypted_balance['data'];
                $iv = $encrypted_name['iv'];
                
                $stmt = $conn->prepare("UPDATE customers SET 
                    encrypted_name = ?, 
                    encrypted_email = ?, 
                    encrypted_phone = ?, 
                    encrypted_account_number = ?, 
                    encrypted_balance = ?, 
                    iv = ? 
                    WHERE customer_id = ?");
                $stmt->bind_param("sssssss", 
                    $enc_name,
                    $enc_email,
                    $enc_phone,
                    $enc_account,
                    $enc_balance,
                    $iv,
                    $customer_id
                );
                
                if ($stmt->execute()) {
                    $message = "✅ Customer updated successfully!";
                } else {
                    $error = "Failed to update customer.";
                }
                $stmt->close();
            } catch (Exception $e) {
                $error = "Encryption error: " . $e->getMessage();
            }
        }
    }
}

// ============================================
// HANDLE DELETE CUSTOMER
// ============================================
if (isset($_POST['delete_customer']) && isset($_POST['customer_id'])) {
    $customer_id = $_POST['customer_id'];
    
    // Check ownership
    $check_stmt = $conn->prepare("SELECT created_by FROM customers WHERE customer_id = ?");
    $check_stmt->bind_param("s", $customer_id);
    $check_stmt->execute();
    $check_result = $check_stmt->get_result();
    $customer_owner = $check_result->fetch_assoc();
    $check_stmt->close();
    
    if (!$customer_owner) {
        $error = "Customer not found.";
    } elseif (!$is_admin && $customer_owner['created_by'] !== $username) {
        $error = "You can only delete customers you created.";
    } else {
        $stmt = $conn->prepare("DELETE FROM customers WHERE customer_id = ?");
        $stmt->bind_param("s", $customer_id);
        if ($stmt->execute()) {
            $message = "✅ Customer deleted successfully!";
            
            $log_stmt = $conn->prepare("INSERT INTO intrusion_logs (ip_address, activity, threat_level, status) VALUES (?, ?, ?, ?)");
            $activity = "User $username deleted customer: $customer_id";
            $threat_level = "Low";
            $status = "Success";
            $log_stmt->bind_param("ssss", $user_ip, $activity, $threat_level, $status);
            $log_stmt->execute();
            $log_stmt->close();
        } else {
            $error = "Failed to delete customer.";
        }
        $stmt->close();
    }
}

// ============================================
// HANDLE VIEW CUSTOMERS
// ============================================
if (isset($_POST['view_customers']) && isset($_POST['decryption_key'])) {
    $provided_key = trim($_POST['decryption_key'] ?? '');
    
    if (empty($provided_key)) {
        $error = "Encryption key is required!";
    } elseif ($provided_key !== $user_key) {
        $error = "Invalid encryption key! Use your personal encryption key.";
    } else {
        // Get customers based on role
        if ($is_admin) {
            // Admin sees ALL customers and can decrypt them with admin key
            $result = $conn->query("SELECT * FROM customers ORDER BY created_at DESC");
        } else {
            // Regular user sees only their own customers
            $stmt = $conn->prepare("SELECT * FROM customers WHERE created_by = ? ORDER BY created_at DESC");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $result = $stmt->get_result();
        }
        
        if ($result && $result->num_rows > 0) {
            $decrypt_count = 0;
            $fail_count = 0;
            
            while ($row = $result->fetch_assoc()) {
                try {
                    $iv = $row['iv'] ?? '';
                    $stored_user_key = $row['user_key'] ?? '';
                    
                    if (empty($iv)) {
                        $row['decrypted_name'] = 'ERROR: Missing IV';
                        $row['decrypted_email'] = 'ERROR: Missing IV';
                        $row['decrypted_phone'] = 'ERROR: Missing IV';
                        $row['decrypted_account'] = 'ERROR: Missing IV';
                        $row['decrypted_balance'] = '0';
                        $fail_count++;
                    } else {
                        // For admin: use admin's key to decrypt (admin key can decrypt all)
                        // For regular users: use their own key
                        $decrypt_key = $user_key;
                        
                        // Decrypt each field
                        $row['decrypted_name'] = $encryption->decrypt($row['encrypted_name'], $decrypt_key, $iv);
                        $row['decrypted_email'] = $encryption->decrypt($row['encrypted_email'], $decrypt_key, $iv);
                        $row['decrypted_phone'] = $encryption->decrypt($row['encrypted_phone'], $decrypt_key, $iv);
                        $row['decrypted_account'] = $encryption->decrypt($row['encrypted_account_number'], $decrypt_key, $iv);
                        $row['decrypted_balance'] = $encryption->decrypt($row['encrypted_balance'], $decrypt_key, $iv);
                        
                        // Check if decryption was successful
                        if ($row['decrypted_name'] === false || $row['decrypted_name'] === null || $row['decrypted_name'] === '') {
                            $row['decrypted_name'] = 'Decryption Failed';
                            $fail_count++;
                        } else {
                            $decrypt_count++;
                        }
                        
                        if ($row['decrypted_email'] === false || $row['decrypted_email'] === null) {
                            $row['decrypted_email'] = 'Decryption Failed';
                        }
                        
                        if ($row['decrypted_phone'] === false || $row['decrypted_phone'] === null) {
                            $row['decrypted_phone'] = 'Decryption Failed';
                        }
                        
                        if ($row['decrypted_account'] === false || $row['decrypted_account'] === null) {
                            $row['decrypted_account'] = 'Decryption Failed';
                        }
                        
                        if ($row['decrypted_balance'] === false || $row['decrypted_balance'] === null) {
                            $row['decrypted_balance'] = '0';
                        }
                    }
                    
                    $row['created_by'] = $row['created_by'] ?? 'Unknown';
                    $decrypted_customers[] = $row;
                    
                } catch (Exception $e) {
                    $fail_count++;
                    $row['decrypted_name'] = 'Error: ' . $e->getMessage();
                    $row['decrypted_email'] = 'Error: ' . $e->getMessage();
                    $row['decrypted_phone'] = 'Error: ' . $e->getMessage();
                    $row['decrypted_account'] = 'Error: ' . $e->getMessage();
                    $row['decrypted_balance'] = '0';
                    $row['created_by'] = $row['created_by'] ?? 'Unknown';
                    $decrypted_customers[] = $row;
                }
            }
            
            $key_required = false;
            
            if ($decrypt_count > 0) {
                $message = "✅ Found " . count($decrypted_customers) . " customer(s). Successfully decrypted: $decrypt_count";
            } elseif ($fail_count > 0 && count($decrypted_customers) > 0) {
                $message = "⚠️ Found " . count($decrypted_customers) . " customer(s) but decryption failed. Make sure you're using the correct encryption key.";
            } else {
                $message = "No customers found.";
            }
            
            // Log successful view
            $log_stmt = $conn->prepare("INSERT INTO intrusion_logs (ip_address, activity, threat_level, status) VALUES (?, ?, ?, ?)");
            $activity = "User $username viewed " . count($decrypted_customers) . " customers";
            $threat_level = "Low";
            $status = "Success";
            $log_stmt->bind_param("ssss", $user_ip, $activity, $threat_level, $status);
            $log_stmt->execute();
            $log_stmt->close();
        } else {
            $message = "No customers found.";
            $key_required = false;
        }
        
        if (!$is_admin && isset($stmt)) {
            $stmt->close();
        }
    }
}

// Get total customers count
$total_customers = 0;
if ($is_admin) {
    $result = $conn->query("SELECT COUNT(*) as total FROM customers");
} else {
    $stmt = $conn->prepare("SELECT COUNT(*) as total FROM customers WHERE created_by = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
}
if ($result && $row = $result->fetch_assoc()) {
    $total_customers = $row['total'];
}
if (!$is_admin && isset($stmt)) {
    $stmt->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Customer Management - MOHAZ BANK</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0f172a;
            color: white;
        }
        
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: 260px;
            height: 100%;
            background: #1e293b;
            overflow-y: auto;
        }
        
        .sidebar-header {
            padding: 20px;
            text-align: center;
            border-bottom: 1px solid #334155;
        }
        
        .sidebar-header h3 {
            color: #38bdf8;
            margin-top: 10px;
        }
        
        .sidebar-menu a {
            display: block;
            padding: 12px 20px;
            color: #cbd5e1;
            text-decoration: none;
            transition: all 0.3s;
        }
        
        .sidebar-menu a:hover, .sidebar-menu a.active {
            background: #334155;
            color: white;
        }
        
        .main-content {
            margin-left: 260px;
            padding: 20px;
        }
        
        .top-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #334155;
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .role-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
        }
        
        .role-admin {
            background: #3b82f6;
            color: white;
        }
        
        .role-user {
            background: #64748b;
            color: white;
        }
        
        .card {
            background: #1e293b;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 30px;
        }
        
        .card h2 {
            color: #38bdf8;
            margin-bottom: 20px;
            border-left: 4px solid #38bdf8;
            padding-left: 15px;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #94a3b8;
            font-weight: 500;
        }
        
        input, select {
            width: 100%;
            padding: 10px;
            background: #0f172a;
            border: 1px solid #334155;
            color: white;
            border-radius: 5px;
            font-size: 14px;
        }
        
        input:focus {
            outline: none;
            border-color: #38bdf8;
        }
        
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            text-decoration: none;
            display: inline-block;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: #3b82f6;
            color: white;
        }
        
        .btn-primary:hover {
            background: #2563eb;
        }
        
        .btn-success {
            background: #22c55e;
            color: white;
        }
        
        .btn-success:hover {
            background: #16a34a;
        }
        
        .btn-danger {
            background: #dc2626;
            color: white;
        }
        
        .btn-danger:hover {
            background: #b91c1c;
        }
        
        .btn-warning {
            background: #f59e0b;
            color: white;
        }
        
        .btn-info {
            background: #06b6d4;
            color: white;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #334155;
        }
        
        th {
            background: #334155;
            color: #38bdf8;
            font-weight: 600;
        }
        
        tr:hover {
            background: #2d3748;
        }
        
        .message {
            background: #22c55e;
            padding: 12px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .error {
            background: #dc2626;
            padding: 12px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .warning {
            background: #fbbf24;
            color: #0f172a;
            padding: 12px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .key-box {
            background: #0f172a;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            word-break: break-all;
            font-family: monospace;
            border-left: 3px solid #22c55e;
        }
        
        .grid-2 {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
            gap: 25px;
        }
        
        .table-responsive {
            overflow-x: auto;
            margin-top: 20px;
        }
        
        .balance-positive {
            color: #4ade80;
            font-weight: bold;
        }
        
        .decryption-warning {
            color: #fbbf24;
            font-style: italic;
        }
        
        .admin-badge {
            background: #3b82f6;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 10px;
            margin-left: 5px;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        
        .modal-content {
            background: #1e293b;
            padding: 30px;
            border-radius: 10px;
            max-width: 500px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
        }
        
        .close {
            float: right;
            font-size: 24px;
            cursor: pointer;
            color: #94a3b8;
        }
        
        .close:hover {
            color: white;
        }
        
        @media (max-width: 768px) {
            .sidebar {
                width: 70px;
            }
            .sidebar-header h3, .sidebar-menu a span {
                display: none;
            }
            .main-content {
                margin-left: 70px;
            }
            .grid-2 {
                grid-template-columns: 1fr;
            }
            th, td {
                padding: 8px;
                font-size: 12px;
            }
        }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="sidebar-header">
            <h2><?php echo $is_admin ? '👑' : '👤'; ?></h2>
            <h3>MOHAZ BANK</h3>
        </div>
      <div class="sidebar-menu">
    <a href="dashboard.php">📊 <span> Dashboard</span></a>
    <a href="customers.php" class="active">👤 <span> My Customers</span></a>
    <a href="view_all_customers.php">👑 <span> All Customers</span></a>
    <?php if ($is_admin): ?>
    <a href="users.php">👥 <span> Manage Users</span></a>
    <a href="logs.php">📋 <span> System Logs</span></a>
    <?php endif; ?>
    <a href="../auth/logout.php">🚪 <span> Logout</span></a>
</div>
    </div>
    
    <div class="main-content">
        <div class="top-header">
            <div>
                <h1>👤 Customer Management</h1>
                <p style="color: #94a3b8;">
                    Role: 
                    <?php if ($is_admin): ?>
                        <span class="role-badge role-admin">👑 Administrator</span>
                        <span style="margin-left: 10px;">🔓 Admin can decrypt ALL customer data</span>
                    <?php else: ?>
                        <span class="role-badge role-user">👤 Regular User</span>
                        <span style="margin-left: 10px;">🔒 View only customers you created</span>
                    <?php endif; ?>
                </p>
            </div>
            <div>
                <span class="btn btn-info" style="background: #334155;">Your Customers: <?php echo $total_customers; ?></span>
                <a href="../auth/logout.php" class="btn btn-danger" style="margin-left: 10px;">Logout</a>
            </div>
        </div>
        
        <!-- User Encryption Key -->
        <div class="card">
            <h2>🔑 Your Personal Encryption Key</h2>
            <div class="key-box" id="userKey"><?php echo htmlspecialchars($user_key); ?></div>
            <button class="btn btn-primary" onclick="copyKey()">📋 Copy Key</button>
            <?php if ($is_admin): ?>
            <div class="warning" style="margin-top: 10px;">
                ⚠️ <strong>ADMIN PRIVILEGE:</strong> Your admin key can decrypt ALL customer data in the system.
            </div>
            <?php else: ?>
            <div class="warning" style="margin-top: 10px;">
                ⚠️ Use this exact key to add and view customers. Keep it secure!
            </div>
            <?php endif; ?>
        </div>
        
        <?php if ($message): ?>
            <div class="message">✅ <?php echo $message; ?></div>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="error">❌ <?php echo $error; ?></div>
        <?php endif; ?>
        
        <div class="grid-2">
            <!-- Add Customer Form -->
            <div class="card">
                <h2>➕ Add New Customer</h2>
                <div class="warning">
                    🔐 All customer data is encrypted with your personal key before storage.
                </div>
                <form method="POST" action="">
                    <div class="form-group">
                        <label>🔑 Your Encryption Key:</label>
                        <input type="password" name="encryption_key" placeholder="Paste your key from above" required>
                    </div>
                    <div class="form-group">
                        <label>Full Name:</label>
                        <input type="text" name="name" required placeholder="John Doe">
                    </div>
                    <div class="form-group">
                        <label>Email:</label>
                        <input type="email" name="email" required placeholder="customer@example.com">
                    </div>
                    <div class="form-group">
                        <label>Phone:</label>
                        <input type="text" name="phone" required placeholder="+234 801 234 5678">
                    </div>
                    <div class="form-group">
                        <label>Account Number:</label>
                        <input type="text" name="account_number" required placeholder="0123456789">
                    </div>
                    <div class="form-group">
                        <label>Balance (₦):</label>
                        <input type="number" name="balance" step="0.01" required placeholder="0.00">
                    </div>
                    <button type="submit" name="add_customer" class="btn btn-success">💾 Add Customer (Encrypt)</button>
                </form>
            </div>
            
            <!-- View Customers Section -->
            <div class="card">
                <h2>🔍 View <?php echo $is_admin ? 'All' : 'Your'; ?> Customers</h2>
                <?php if ($key_required): ?>
                    <div class="warning">
                        🔐 Enter your personal encryption key to decrypt and view your customers.
                        <?php if ($is_admin): ?>
                        <br><strong>Admin Note:</strong> Your admin key can decrypt ALL customers in the system.
                        <?php endif; ?>
                    </div>
                    <form method="POST" action="">
                        <div class="form-group">
                            <label>🔑 Your Encryption Key:</label>
                            <input type="password" name="decryption_key" placeholder="Paste your key from above" required>
                        </div>
                        <button type="submit" name="view_customers" class="btn btn-primary">🔓 Decrypt & View Customers</button>
                    </form>
                <?php else: ?>
                    <?php if (count($decrypted_customers) > 0): ?>
                        <div class="table-responsive">
                            <table id="customersTable">
                                <thead>
                                    <tr>
                                        <th>Customer ID</th>
                                        <th>Name</th>
                                        <th>Email</th>
                                        <th>Phone</th>
                                        <th>Account Number</th>
                                        <th>Balance</th>
                                        <th>Created By</th>
                                        <th>Created Date</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($decrypted_customers as $c): ?>
                                    <tr>
                                        <td class="customer-id"><?php echo htmlspecialchars($c['customer_id']); ?></td>
                                        <td>
                                            <?php 
                                            $name = htmlspecialchars($c['decrypted_name']);
                                            if (strpos($name, 'Failed') !== false) {
                                                echo '<span class="decryption-warning">⚠️ ' . $name . '</span>';
                                            } else {
                                                echo '<strong>' . $name . '</strong>';
                                            }
                                            ?>
                                        </td>
                                        <td>
                                            <?php 
                                            $email = htmlspecialchars($c['decrypted_email']);
                                            if (strpos($email, 'Failed') !== false) {
                                                echo '<span class="decryption-warning">📧 ' . $email . '</span>';
                                            } else {
                                                echo '📧 ' . $email;
                                            }
                                            ?>
                                        </td>
                                        <td>
                                            <?php 
                                            $phone = htmlspecialchars($c['decrypted_phone']);
                                            if (strpos($phone, 'Failed') !== false) {
                                                echo '<span class="decryption-warning">📱 ' . $phone . '</span>';
                                            } else {
                                                echo '📱 ' . $phone;
                                            }
                                            ?>
                                        </td>
                                        <td>
                                            <?php 
                                            $account = htmlspecialchars($c['decrypted_account']);
                                            if (strpos($account, 'Failed') !== false) {
                                                echo '<span class="decryption-warning">💳 ' . $account . '</span>';
                                            } else {
                                                echo '💳 ' . $account;
                                            }
                                            ?>
                                        </td>
                                        <td class="balance-positive">₦ <?php echo number_format(floatval($c['decrypted_balance']), 2); ?></td>
                                        <td>
                                            <?php echo htmlspecialchars($c['created_by']); ?>
                                            <?php if ($is_admin && $c['created_by'] !== $username): ?>
                                                <span class="admin-badge">(by user)</span>
                                            <?php endif; ?>
                                        </td>
                                        <td><?php echo date('Y-m-d', strtotime($c['created_at'])); ?></td>
                                        <td>
                                            <?php if ($is_admin || $c['created_by'] === $username): ?>
                                            <button class="btn btn-warning" onclick="editCustomer('<?php echo $c['customer_id']; ?>', '<?php echo addslashes($c['decrypted_name']); ?>', '<?php echo addslashes($c['decrypted_email']); ?>', '<?php echo addslashes($c['decrypted_phone']); ?>', '<?php echo addslashes($c['decrypted_account']); ?>', '<?php echo $c['decrypted_balance']; ?>')">✏️ Edit</button>
                                            <form method="POST" style="display: inline;" onsubmit="return confirm('Delete this customer? This cannot be undone.');">
                                                <input type="hidden" name="customer_id" value="<?php echo $c['customer_id']; ?>">
                                                <button type="submit" name="delete_customer" class="btn btn-danger">🗑️ Delete</button>
                                            </form>
                                            <?php else: ?>
                                            <span class="decryption-warning">Read only</span>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                        
                        <div style="margin-top: 15px; text-align: center; color: #94a3b8;">
                            Showing <?php echo count($decrypted_customers); ?> of <?php echo $total_customers; ?> total customers
                        </div>
                    <?php else: ?>
                        <div style="text-align: center; padding: 40px;">
                            <div style="font-size: 48px; margin-bottom: 20px;">📭</div>
                            <p>No customers found.</p>
                            <p style="color: #94a3b8; margin-top: 10px;">Add your first customer using the form on the left.</p>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>
        
        <!-- Edit Customer Modal -->
        <div id="editModal" class="modal">
            <div class="modal-content">
                <span class="close" onclick="closeModal()">&times;</span>
                <h2>✏️ Edit Customer</h2>
                <form method="POST" action="" id="editForm">
                    <input type="hidden" name="customer_id" id="edit_customer_id">
                    <div class="form-group">
                        <label>🔑 Your Encryption Key:</label>
                        <input type="password" name="encryption_key" placeholder="Paste your key from above" required>
                    </div>
                    <div class="form-group">
                        <label>Full Name:</label>
                        <input type="text" name="name" id="edit_name" required>
                    </div>
                    <div class="form-group">
                        <label>Email:</label>
                        <input type="email" name="email" id="edit_email" required>
                    </div>
                    <div class="form-group">
                        <label>Phone:</label>
                        <input type="text" name="phone" id="edit_phone" required>
                    </div>
                    <div class="form-group">
                        <label>Account Number:</label>
                        <input type="text" name="account_number" id="edit_account" required>
                    </div>
                    <div class="form-group">
                        <label>Balance (₦):</label>
                        <input type="number" name="balance" step="0.01" id="edit_balance" required>
                    </div>
                    <button type="submit" name="edit_customer" class="btn btn-success">💾 Update Customer</button>
                    <button type="button" class="btn btn-danger" onclick="closeModal()">Cancel</button>
                </form>
            </div>
        </div>
        
        <!-- Information Section -->
        <div class="card">
            <h2>ℹ️ System Information</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
                <div style="background: #0f172a; padding: 15px; border-radius: 8px;">
                    <strong>🔐 Encryption System:</strong>
                    <ul style="margin-top: 10px; margin-left: 20px; color: #94a3b8;">
                        <li>Algorithm: AES-256-CBC</li>
                        <li>Key Length: 64 characters (256-bit)</li>
                        <li>Each user has unique encryption key</li>
                        <li>Data encrypted before storage</li>
                    </ul>
                </div>
                <div style="background: #0f172a; padding: 15px; border-radius: 8px;">
                    <strong>👑 Admin Privileges:</strong>
                    <ul style="margin-top: 10px; margin-left: 20px; color: #94a3b8;">
                        <li>✅ Admin can view ALL customers</li>
                        <li>✅ Admin can decrypt ALL customer data</li>
                        <li>✅ Admin can edit/delete any customer</li>
                        <li>✅ Admin can manage users</li>
                    </ul>
                </div>
                <div style="background: #0f172a; padding: 15px; border-radius: 8px;">
                    <strong>👤 Regular User Access:</strong>
                    <ul style="margin-top: 10px; margin-left: 20px; color: #94a3b8;">
                        <li>✅ View only customers you created</li>
                        <li>✅ Add new customers (encrypted with your key)</li>
                        <li>✅ Edit/delete your own customers</li>
                        <li>❌ Cannot view other users' customers</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function copyKey() {
            const key = document.getElementById('userKey').innerText;
            navigator.clipboard.writeText(key).then(() => {
                alert('Encryption key copied to clipboard!');
            });
        }
        
        function editCustomer(id, name, email, phone, account, balance) {
            document.getElementById('edit_customer_id').value = id;
            document.getElementById('edit_name').value = name;
            document.getElementById('edit_email').value = email;
            document.getElementById('edit_phone').value = phone;
            document.getElementById('edit_account').value = account;
            document.getElementById('edit_balance').value = balance;
            document.getElementById('editModal').style.display = 'flex';
        }
        
        function closeModal() {
            document.getElementById('editModal').style.display = 'none';
        }
        
        window.onclick = function(event) {
            if (event.target.classList.contains('modal')) {
                closeModal();
            }
        }
    </script>
</body>
</html>