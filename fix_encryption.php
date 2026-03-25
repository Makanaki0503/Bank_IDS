<?php
session_start();
include("config/db.php");
include("includes/check_role.php");

// Only admin can run this
requireAdmin();

$admin_username = getUsername();
$message = '';
$error = '';

// Get admin's encryption key
$stmt = $conn->prepare("SELECT encryption_key FROM users WHERE username = ?");
$stmt->bind_param("s", $admin_username);
$stmt->execute();
$result = $stmt->get_result();
$admin = $result->fetch_assoc();
$admin_key = $admin['encryption_key'] ?? '';
$stmt->close();

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['fix_encryption'])) {
    // Get all customers
    $customers = $conn->query("SELECT * FROM customers");
    $fixed_count = 0;
    $failed_count = 0;
    
    if ($customers && $customers->num_rows > 0) {
        while ($customer = $customers->fetch_assoc()) {
            $customer_id = $customer['customer_id'];
            $iv = $customer['iv'] ?? '';
            $user_key = $customer['user_key'] ?? '';
            
            if (empty($iv)) {
                $failed_count++;
                continue;
            }
            
            // Try to decrypt with original user key first
            try {
                // Decrypt with original user key
                $name = $encryption->decrypt($customer['encrypted_name'], $user_key, $iv);
                $email = $encryption->decrypt($customer['encrypted_email'], $user_key, $iv);
                $phone = $encryption->decrypt($customer['encrypted_phone'], $user_key, $iv);
                $account = $encryption->decrypt($customer['encrypted_account_number'], $user_key, $iv);
                $balance = $encryption->decrypt($customer['encrypted_balance'], $user_key, $iv);
                
                if ($name !== false && $name !== null && $name !== '') {
                    // Re-encrypt with admin key
                    $encrypted_name = $encryption->encrypt($name, $admin_key);
                    $encrypted_email = $encryption->encrypt($email, $admin_key);
                    $encrypted_phone = $encryption->encrypt($phone, $admin_key);
                    $encrypted_account = $encryption->encrypt($account, $admin_key);
                    $encrypted_balance = $encryption->encrypt($balance, $admin_key);
                    
                    $update_stmt = $conn->prepare("UPDATE customers SET 
                        encrypted_name = ?,
                        encrypted_email = ?,
                        encrypted_phone = ?,
                        encrypted_account_number = ?,
                        encrypted_balance = ?,
                        iv = ?,
                        user_key = ?
                        WHERE customer_id = ?");
                    
                    $update_stmt->bind_param("ssssssss", 
                        $encrypted_name['data'],
                        $encrypted_email['data'],
                        $encrypted_phone['data'],
                        $encrypted_account['data'],
                        $encrypted_balance['data'],
                        $encrypted_name['iv'],
                        $admin_key,
                        $customer_id
                    );
                    
                    if ($update_stmt->execute()) {
                        $fixed_count++;
                    } else {
                        $failed_count++;
                    }
                    $update_stmt->close();
                } else {
                    $failed_count++;
                }
            } catch (Exception $e) {
                $failed_count++;
            }
        }
    }
    
    $message = "✅ Fixed $fixed_count customers. Failed: $failed_count";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fix Encryption - MOHAZ BANK</title>
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
            padding: 20px;
        }
        
        .container {
            max-width: 800px;
            margin: 50px auto;
            background: #1e293b;
            border-radius: 10px;
            padding: 30px;
        }
        
        h1 {
            color: #38bdf8;
            margin-bottom: 20px;
        }
        
        .key-box {
            background: #0f172a;
            padding: 15px;
            border-radius: 8px;
            font-family: monospace;
            word-break: break-all;
            margin: 15px 0;
        }
        
        .warning {
            background: #fbbf24;
            color: #0f172a;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
        }
        
        .message {
            background: #22c55e;
            padding: 12px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .btn {
            background: #22c55e;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
        }
        
        .btn-danger {
            background: #dc2626;
        }
        
        .btn-primary {
            background: #3b82f6;
        }
        
        .button-group {
            display: flex;
            gap: 15px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔧 Fix Customer Encryption</h1>
        
        <div class="key-box">
            <strong>Admin Encryption Key:</strong><br>
            <?php echo htmlspecialchars($admin_key); ?>
        </div>
        
        <div class="warning">
            ⚠️ <strong>Warning:</strong> This will re-encrypt all existing customers with your admin key.<br>
            After this, regular users will NOT be able to view customers they created.<br>
            Only admin will be able to view all customers.
        </div>
        
        <?php if ($message): ?>
            <div class="message"><?php echo $message; ?></div>
        <?php endif; ?>
        
        <form method="POST">
            <button type="submit" name="fix_encryption" class="btn" onclick="return confirm('This will re-encrypt ALL customers with admin key. Regular users will lose access. Continue?')">
                🔓 Re-encrypt All Customers with Admin Key
            </button>
        </form>
        
        <div class="button-group">
            <a href="admin/customers.php" class="btn btn-primary" style="text-decoration: none; display: inline-block;">📊 Go to Customer Management</a>
            <a href="admin/dashboard.php" class="btn btn-primary" style="text-decoration: none; display: inline-block;">🏠 Back to Dashboard</a>
        </div>
    </div>
</body>
</html>