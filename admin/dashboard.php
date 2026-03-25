<?php
session_start();
include(__DIR__ . "/../config/db.php");
include(__DIR__ . "/../includes/check_role.php");

// Check if user is logged in
requireLogin();

// Check session expiry
checkSession();

// Get user info
$username = getUsername();
$user_role = getUserRole();
$is_admin = isAdmin();

// Get statistics based on role
$total_customers = 0;
$intrusion_count = 0;
$blocked_ips = 0;
$total_users = 0;

$result = $conn->query("SELECT COUNT(*) as total FROM customers");
if ($result && $row = $result->fetch_assoc()) {
    $total_customers = $row['total'];
}

// Only admin can see system statistics
if ($is_admin) {
    $result = $conn->query("SELECT COUNT(*) as total FROM users");
    if ($result && $row = $result->fetch_assoc()) {
        $total_users = $row['total'];
    }
    
    $result = $conn->query("SELECT COUNT(*) as total FROM intrusion_logs");
    if ($result && $row = $result->fetch_assoc()) {
        $intrusion_count = $row['total'];
    }
    
    $result = $conn->query("SELECT COUNT(*) as total FROM blocked_ips WHERE expires_at > NOW() OR expires_at IS NULL");
    if ($result && $row = $result->fetch_assoc()) {
        $blocked_ips = $row['total'];
    }
} else {
    // Regular users only see their own activity
    $result = $conn->query("SELECT COUNT(*) as total FROM intrusion_logs WHERE ip_address = '{$_SERVER['REMOTE_ADDR']}'");
    if ($result && $row = $result->fetch_assoc()) {
        $intrusion_count = $row['total'];
    }
}

// Get recent intrusions based on role
if ($is_admin) {
    $intrusions = $conn->query("SELECT * FROM intrusion_logs ORDER BY created_at DESC LIMIT 10");
} else {
    // Regular users only see their own IP's intrusions
    $ip = $_SERVER['REMOTE_ADDR'];
    $intrusions = $conn->query("SELECT * FROM intrusion_logs WHERE ip_address = '$ip' ORDER BY created_at DESC LIMIT 10");
}

// Get user's encryption key
$my_key = '';
$stmt = $conn->prepare("SELECT encryption_key FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();
if ($row = $result->fetch_assoc()) {
    $my_key = $row['encryption_key'];
}
$stmt->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - MOHAZ BANK IDPS</title>
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
        
        /* Sidebar */
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: 260px;
            height: 100%;
            background: #1e293b;
            overflow-y: auto;
            transition: all 0.3s;
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
        
        .sidebar-menu a:hover {
            background: #334155;
            color: white;
            padding-left: 25px;
        }
        
        .sidebar-menu a.active {
            background: #22c55e;
            color: white;
        }
        
        .role-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            margin-left: 10px;
        }
        
        .role-admin {
            background: #3b82f6;
            color: white;
        }
        
        .role-user {
            background: #64748b;
            color: white;
        }
        
        /* Main Content */
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
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .logout-btn {
            background: #dc2626;
            color: white;
            padding: 8px 16px;
            text-decoration: none;
            border-radius: 5px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: #1e293b;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-number {
            font-size: 32px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .stat-label {
            color: #94a3b8;
            font-size: 14px;
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
        
        .warning {
            background: #fbbf24;
            color: #0f172a;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        .key-display {
            background: #0f172a;
            padding: 15px;
            border-radius: 8px;
            font-family: monospace;
            word-break: break-all;
            margin: 15px 0;
        }
        
        .key-blur {
            filter: blur(4px);
            user-select: none;
        }
        
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        
        .btn-primary {
            background: #3b82f6;
            color: white;
        }
        
        .btn-success {
            background: #22c55e;
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
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-header">
            <h2>🔐</h2>
            <h3>MOHAZ BANK</h3>
        </div>
       <div class="sidebar-menu">
    <a href="dashboard.php" class="active">📊 <span> Dashboard</span></a>
    <a href="customers.php">👤 <span> My Customers</span></a>
    <a href="view_all_customers.php">👑 <span> All Customers</span></a>
    <?php if ($is_admin): ?>
    <a href="users.php">👥 <span> Manage Users</span></a>
    <a href="logs.php">📋 <span> System Logs</span></a>
    <?php endif; ?>
    <a href="../auth/logout.php">🚪 <span> Logout</span></a>
</div>
    </div>
    
    <!-- Main Content -->
    <div class="main-content">
        <div class="top-header">
            <div>
                <h1>Welcome, <?php echo htmlspecialchars($username); ?></h1>
                <p style="color: #94a3b8;">
                    Role: 
                    <?php if ($is_admin): ?>
                        <span class="role-badge role-admin">👑 Administrator</span>
                        <span style="color: #94a3b8; margin-left: 10px;">Full system access</span>
                    <?php else: ?>
                        <span class="role-badge role-user">👤 Regular User</span>
                        <span style="color: #94a3b8; margin-left: 10px;">Limited access - View only your data</span>
                    <?php endif; ?>
                </p>
            </div>
            <div class="user-info">
                <span>Logged in as: <strong><?php echo htmlspecialchars($username); ?></strong></span>
                <a href="../auth/logout.php" class="logout-btn">Logout</a>
            </div>
        </div>
        
        <!-- Admin Notice for Regular Users -->
        <?php if (!$is_admin): ?>
        <div class="warning">
            ℹ️ You are logged in as a <strong>Regular User</strong>. Some administrative features are not available.
            Contact your system administrator if you need additional permissions.
        </div>
        <?php endif; ?>
        
        <!-- Your Encryption Key (Same for all users) -->
        <div class="card">
            <h2>🔑 YOUR PERSONAL ENCRYPTION KEY</h2>
            <div class="key-display key-blur" id="myKey">
                <?php echo htmlspecialchars($my_key); ?>
            </div>
            <button class="btn btn-success" onclick="copyKey()">📋 Copy Key</button>
            <button class="btn btn-primary" onclick="toggleKey()">👁️ Show/Hide</button>
            <div class="warning" style="margin-top: 15px; font-size: 12px;">
                ⚠️ This key is required to decrypt and view customer data. Keep it secure!
            </div>
        </div>
        
        <!-- Statistics - Different for Admin vs Regular User -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number" style="color: #38bdf8;"><?php echo $total_customers; ?></div>
                <div class="stat-label">Total Customers</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #f87171;"><?php echo $intrusion_count; ?></div>
                <div class="stat-label">Intrusion Attempts</div>
            </div>
            <?php if ($is_admin): ?>
            <div class="stat-card">
                <div class="stat-number" style="color: #fbbf24;"><?php echo $blocked_ips; ?></div>
                <div class="stat-label">Blocked IPs</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #4ade80;"><?php echo $total_users; ?></div>
                <div class="stat-label">System Users</div>
            </div>
            <?php endif; ?>
        </div>
        
        <!-- Recent Intrusions - Different for Admin vs Regular User -->
        <div class="card">
            <h2>🛡️ Recent Intrusion Detection Logs</h2>
            <div class="table-responsive">
                <?php if ($intrusions && $intrusions->num_rows > 0): ?>
                <table>
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Activity</th>
                            <th>Threat Level</th>
                            <th>Time</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while ($log = $intrusions->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($log['ip_address']); ?></td>
                            <td><?php echo htmlspecialchars(substr($log['activity'], 0, 50)); ?></td>
                            <td style="color: <?php echo $log['threat_level'] == 'Critical' ? '#dc2626' : '#fbbf24'; ?>">
                                <?php echo $log['threat_level']; ?>
                            </td>
                            <td><?php echo date('H:i:s', strtotime($log['created_at'])); ?></td>
                        </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
                <?php else: ?>
                <p>✅ No intrusion attempts detected.</p>
                <?php endif; ?>
            </div>
        </div>
        
        <!-- Role-Specific Information -->
        <div class="card">
            <h2>📋 Your Access Level</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px;">
                <?php if ($is_admin): ?>
                <div style="background: #0f172a; padding: 15px; border-radius: 8px;">
                    <strong style="color: #38bdf8;">👑 Administrator Access</strong>
                    <ul style="margin-top: 10px; margin-left: 20px; color: #94a3b8;">
                        <li>✅ View all system logs</li>
                        <li>✅ Manage all users</li>
                        <li>✅ View and edit all customers</li>
                        <li>✅ Block/unblock IP addresses</li>
                        <li>✅ View system statistics</li>
                        <li>✅ Configure system settings</li>
                    </ul>
                </div>
                <?php else: ?>
                <div style="background: #0f172a; padding: 15px; border-radius: 8px;">
                    <strong style="color: #fbbf24;">👤 Regular User Access</strong>
                    <ul style="margin-top: 10px; margin-left: 20px; color: #94a3b8;">
                        <li>✅ View your own customers</li>
                        <li>✅ Add new customers</li>
                        <li>✅ View your own activity logs</li>
                        <li>✅ Manage your profile</li>
                        <li>❌ Cannot manage other users</li>
                        <li>❌ Cannot view system logs</li>
                    </ul>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <script>
        function copyKey() {
            const key = document.getElementById('myKey').innerText;
            navigator.clipboard.writeText(key).then(() => alert('Key copied!'));
        }
        
        function toggleKey() {
            const key = document.getElementById('myKey');
            key.classList.toggle('key-blur');
        }
    </script>
</body>
</html>