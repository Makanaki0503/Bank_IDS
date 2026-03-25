<?php
session_start();
include(__DIR__ . "/../config/db.php");

// Check if user is logged in and is admin
if (!isset($_SESSION['user'])) {
    header("Location: ../auth/login.php");
    exit();
}

// Verify admin role
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
    // Create user
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
                $message = "✅ User created successfully!";
                $new_user_key = $encryption_key;
            } else {
                $error = "Username already exists.";
            }
            $stmt->close();
        } else {
            $error = "Username (min 3) and password (min 6) required.";
        }
    }
    
    // Delete user
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
    
    // Reset user password
    if (isset($_POST['reset_password']) && isset($_POST['user_id'])) {
        $user_id = intval($_POST['user_id']);
        $new_password = $_POST['new_password'];
        
        if (strlen($new_password) >= 6) {
            $hashed_password = password_hash($new_password, PASSWORD_BCRYPT);
            $stmt = $conn->prepare("UPDATE users SET password = ? WHERE id = ?");
            $stmt->bind_param("si", $hashed_password, $user_id);
            if ($stmt->execute()) {
                $message = "Password reset successfully.";
            } else {
                $error = "Failed to reset password.";
            }
            $stmt->close();
        } else {
            $error = "Password must be at least 6 characters.";
        }
    }
    
    // Change user role
    if (isset($_POST['change_role']) && isset($_POST['user_id'])) {
        $user_id = intval($_POST['user_id']);
        $new_role = $_POST['new_role'];
        
        if ($user_id != $_SESSION['user_id'] ?? 0) {
            $stmt = $conn->prepare("UPDATE users SET role = ? WHERE id = ?");
            $stmt->bind_param("si", $new_role, $user_id);
            if ($stmt->execute()) {
                $message = "User role updated successfully.";
            } else {
                $error = "Failed to update role.";
            }
            $stmt->close();
        } else {
            $error = "You cannot change your own role.";
        }
    }
    
    // Regenerate encryption key
    if (isset($_POST['regenerate_key']) && isset($_POST['user_id'])) {
        $user_id = intval($_POST['user_id']);
        $new_key = bin2hex(openssl_random_pseudo_bytes(32));
        
        $stmt = $conn->prepare("UPDATE users SET encryption_key = ? WHERE id = ?");
        $stmt->bind_param("si", $new_key, $user_id);
        if ($stmt->execute()) {
            $message = "Encryption key regenerated successfully.<br>New Key: <code>$new_key</code>";
        } else {
            $error = "Failed to regenerate key.";
        }
        $stmt->close();
    }
}

// Get all users
$users = $conn->query("SELECT id, username, role, encryption_key, created_at FROM users ORDER BY id DESC");
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management - MOHAZ BANK</title>
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
        }
        
        input, select {
            width: 100%;
            padding: 10px;
            background: #0f172a;
            border: 1px solid #334155;
            color: white;
            border-radius: 5px;
        }
        
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
        }
        
        .btn-primary {
            background: #3b82f6;
            color: white;
        }
        
        .btn-success {
            background: #22c55e;
            color: white;
        }
        
        .btn-danger {
            background: #dc2626;
            color: white;
        }
        
        .btn-warning {
            background: #f59e0b;
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
        
        .badge-admin {
            background: #3b82f6;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
        }
        
        .badge-user {
            background: #64748b;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
        }
        
        .table-responsive {
            overflow-x: auto;
        }
        
        .key-cell {
            font-family: monospace;
            font-size: 11px;
            max-width: 200px;
            word-break: break-all;
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
            max-width: 400px;
            width: 90%;
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
        }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="sidebar-header">
            <h2>🔐</h2>
            <h3>MOHAZ BANK</h3>
        </div>
        <div class="sidebar-menu">
    <a href="dashboard.php">📊 <span> Dashboard</span></a>
    <a href="customers.php">👤 <span> My Customers</span></a>
    <a href="view_all_customers.php">👑 <span> All Customers</span></a>
    <a href="users.php" class="active">👥 <span> Manage Users</span></a>
    <a href="logs.php">📋 <span> System Logs</span></a>
    <a href="../auth/logout.php">🚪 <span> Logout</span></a>
</div>
    </div>
    
    <div class="main-content">
        <div class="top-header">
            <h1>👥 User Management</h1>
            <a href="../auth/logout.php" class="btn btn-danger">Logout</a>
        </div>
        
        <?php if ($message): ?>
            <div class="message">✅ <?php echo $message; ?></div>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="error">❌ <?php echo $error; ?></div>
        <?php endif; ?>
        
        <!-- Create User Form -->
        <div class="card">
            <h2>➕ Create New User</h2>
            <form method="POST" style="display: grid; grid-template-columns: 1fr 1fr 1fr auto; gap: 15px; align-items: end;">
                <div class="form-group" style="margin-bottom: 0;">
                    <label>Username</label>
                    <input type="text" name="username" required placeholder="Enter username">
                </div>
                <div class="form-group" style="margin-bottom: 0;">
                    <label>Password</label>
                    <input type="password" name="password" required placeholder="Min 6 characters">
                </div>
                <div class="form-group" style="margin-bottom: 0;">
                    <label>Role</label>
                    <select name="role">
                        <option value="user">Regular User</option>
                        <option value="admin">Administrator</option>
                    </select>
                </div>
                <button type="submit" name="create_user" class="btn btn-success">Create User</button>
            </form>
        </div>
        
        <!-- Users List -->
        <div class="card">
            <h2>📋 System Users</h2>
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Role</th>
                            <th>Encryption Key</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while ($user = $users->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo $user['id']; ?></td>
                            <td>
                                <?php echo htmlspecialchars($user['username']); ?>
                                <?php if ($user['username'] == $_SESSION['user']): ?>
                                    <span style="color: #4ade80;"> (You)</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ($user['role'] == 'admin'): ?>
                                    <span class="badge-admin">👑 Admin</span>
                                <?php else: ?>
                                    <span class="badge-user">👤 User</span>
                                <?php endif; ?>
                            </td>
                            <td class="key-cell">
                                <code><?php echo substr($user['encryption_key'], 0, 30) . '...'; ?></code>
                            </td>
                            <td><?php echo date('Y-m-d', strtotime($user['created_at'])); ?></td>
                            <td>
                                <?php if ($user['username'] != $_SESSION['user']): ?>
                                <button class="btn btn-warning" onclick="showResetModal(<?php echo $user['id']; ?>, '<?php echo $user['username']; ?>')">🔑 Reset Password</button>
                                <button class="btn btn-primary" onclick="showRoleModal(<?php echo $user['id']; ?>, '<?php echo $user['role']; ?>')">🔄 Change Role</button>
                                <button class="btn btn-danger" onclick="showDeleteModal(<?php echo $user['id']; ?>, '<?php echo $user['username']; ?>')">🗑️ Delete</button>
                                <button class="btn btn-warning" onclick="showKeyModal(<?php echo $user['id']; ?>, '<?php echo $user['username']; ?>')">🔐 Regenerate Key</button>
                                <?php else: ?>
                                    <span style="color: #94a3b8;">Current Account</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <!-- Modals -->
    <div id="resetModal" class="modal">
        <div class="modal-content">
            <h3>Reset Password</h3>
            <form method="POST">
                <input type="hidden" name="user_id" id="reset_user_id">
                <div class="form-group">
                    <label>New Password (min 6 chars):</label>
                    <input type="password" name="new_password" required>
                </div>
                <button type="submit" name="reset_password" class="btn btn-primary">Reset Password</button>
                <button type="button" class="btn btn-danger" onclick="closeModals()">Cancel</button>
            </form>
        </div>
    </div>
    
    <div id="roleModal" class="modal">
        <div class="modal-content">
            <h3>Change User Role</h3>
            <form method="POST">
                <input type="hidden" name="user_id" id="role_user_id">
                <div class="form-group">
                    <label>Select Role:</label>
                    <select name="new_role">
                        <option value="user">Regular User</option>
                        <option value="admin">Administrator</option>
                    </select>
                </div>
                <button type="submit" name="change_role" class="btn btn-primary">Update Role</button>
                <button type="button" class="btn btn-danger" onclick="closeModals()">Cancel</button>
            </form>
        </div>
    </div>
    
    <div id="deleteModal" class="modal">
        <div class="modal-content">
            <h3>Delete User</h3>
            <p>Are you sure you want to delete user: <strong id="delete_username"></strong>?</p>
            <form method="POST">
                <input type="hidden" name="user_id" id="delete_user_id">
                <button type="submit" name="delete_user" class="btn btn-danger">Yes, Delete</button>
                <button type="button" class="btn btn-primary" onclick="closeModals()">Cancel</button>
            </form>
        </div>
    </div>
    
    <div id="keyModal" class="modal">
        <div class="modal-content">
            <h3>Regenerate Encryption Key</h3>
            <p>⚠️ Warning: Regenerating the encryption key will make all previously encrypted customer data unreadable!</p>
            <p>User: <strong id="key_username"></strong></p>
            <form method="POST">
                <input type="hidden" name="user_id" id="key_user_id">
                <button type="submit" name="regenerate_key" class="btn btn-warning">Yes, Regenerate Key</button>
                <button type="button" class="btn btn-primary" onclick="closeModals()">Cancel</button>
            </form>
        </div>
    </div>
    
    <script>
        function showResetModal(userId, username) {
            document.getElementById('reset_user_id').value = userId;
            document.getElementById('resetModal').style.display = 'flex';
        }
        
        function showRoleModal(userId, currentRole) {
            document.getElementById('role_user_id').value = userId;
            document.getElementById('roleModal').style.display = 'flex';
            document.querySelector('#roleModal select[name="new_role"]').value = currentRole;
        }
        
        function showDeleteModal(userId, username) {
            document.getElementById('delete_user_id').value = userId;
            document.getElementById('delete_username').textContent = username;
            document.getElementById('deleteModal').style.display = 'flex';
        }
        
        function showKeyModal(userId, username) {
            document.getElementById('key_user_id').value = userId;
            document.getElementById('key_username').textContent = username;
            document.getElementById('keyModal').style.display = 'flex';
        }
        
        function closeModals() {
            document.querySelectorAll('.modal').forEach(modal => {
                modal.style.display = 'none';
            });
        }
        
        window.onclick = function(event) {
            if (event.target.classList.contains('modal')) {
                closeModals();
            }
        }
    </script>
</body>
</html>