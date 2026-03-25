<?php
session_start();
include(__DIR__ . "/../config/db.php");

// Check if user is logged in
if (!isset($_SESSION['user'])) {
    header("Location: ../auth/login.php");
    exit();
}

// Check if user is admin (logs should be admin-only)
$is_admin = false;
$stmt = $conn->prepare("SELECT role FROM users WHERE username = ?");
$stmt->bind_param("s", $_SESSION['user']);
$stmt->execute();
$result = $stmt->get_result();
if ($user = $result->fetch_assoc()) {
    $is_admin = ($user['role'] == 'admin');
}
$stmt->close();

// If not admin, redirect to dashboard
if (!$is_admin) {
    header("Location: dashboard.php");
    exit();
}

// Handle log actions
$message = '';
$error = '';

// Clear logs
if (isset($_POST['clear_logs']) && isset($_POST['log_type'])) {
    $log_type = $_POST['log_type'];
    try {
        if ($log_type == 'intrusion') {
            $conn->query("TRUNCATE TABLE intrusion_logs");
            $message = "✅ Intrusion logs cleared successfully!";
        } elseif ($log_type == 'failed') {
            $conn->query("TRUNCATE TABLE failed_logins");
            $message = "✅ Failed login logs cleared successfully!";
        } elseif ($log_type == 'blocked') {
            $conn->query("TRUNCATE TABLE blocked_ips");
            $message = "✅ Blocked IPs cleared successfully!";
        } elseif ($log_type == 'all') {
            $conn->query("TRUNCATE TABLE intrusion_logs");
            $conn->query("TRUNCATE TABLE failed_logins");
            $conn->query("TRUNCATE TABLE blocked_ips");
            $message = "✅ All logs cleared successfully!";
        }
    } catch (Exception $e) {
        $error = "Error clearing logs: " . $e->getMessage();
    }
}

// Export logs
if (isset($_POST['export_logs']) && isset($_POST['log_type'])) {
    $log_type = $_POST['log_type'];
    $filename = "mohaz_bank_{$log_type}_logs_" . date('Y-m-d_H-i-s') . ".csv";
    
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    
    $output = fopen('php://output', 'w');
    
    if ($log_type == 'intrusion') {
        fputcsv($output, ['ID', 'IP Address', 'Activity', 'Threat Level', 'Status', 'Timestamp']);
        $result = $conn->query("SELECT * FROM intrusion_logs ORDER BY created_at DESC");
        while ($row = $result->fetch_assoc()) {
            fputcsv($output, [$row['id'], $row['ip_address'], $row['activity'], $row['threat_level'], $row['status'], $row['created_at']]);
        }
    } elseif ($log_type == 'failed') {
        fputcsv($output, ['ID', 'IP Address', 'Username', 'User Agent', 'Timestamp']);
        $result = $conn->query("SELECT * FROM failed_logins ORDER BY created_at DESC");
        while ($row = $result->fetch_assoc()) {
            fputcsv($output, [$row['id'], $row['ip_address'], $row['username'], $row['user_agent'], $row['created_at']]);
        }
    } elseif ($log_type == 'blocked') {
        fputcsv($output, ['ID', 'IP Address', 'Expires At', 'Created At']);
        $result = $conn->query("SELECT * FROM blocked_ips ORDER BY created_at DESC");
        while ($row = $result->fetch_assoc()) {
            fputcsv($output, [$row['id'], $row['ip_address'], $row['expires_at'], $row['created_at']]);
        }
    }
    
    fclose($output);
    exit();
}

// Get filter parameters
$filter_type = isset($_GET['filter']) ? $_GET['filter'] : 'all';
$search = isset($_GET['search']) ? $_GET['search'] : '';
$date_from = isset($_GET['date_from']) ? $_GET['date_from'] : '';
$date_to = isset($_GET['date_to']) ? $_GET['date_to'] : '';

// Build query for intrusion logs
$intrusion_query = "SELECT * FROM intrusion_logs WHERE 1=1";
if ($filter_type != 'all' && $filter_type != '') {
    $intrusion_query .= " AND threat_level = '" . $conn->real_escape_string($filter_type) . "'";
}
if ($search) {
    $intrusion_query .= " AND (ip_address LIKE '%$search%' OR activity LIKE '%$search%')";
}
if ($date_from) {
    $intrusion_query .= " AND DATE(created_at) >= '$date_from'";
}
if ($date_to) {
    $intrusion_query .= " AND DATE(created_at) <= '$date_to'";
}
$intrusion_query .= " ORDER BY created_at DESC LIMIT 500";

$intrusion_logs = $conn->query($intrusion_query);

// Get failed login logs
$failed_query = "SELECT * FROM failed_logins WHERE 1=1";
if ($search) {
    $failed_query .= " AND (ip_address LIKE '%$search%' OR username LIKE '%$search%')";
}
if ($date_from) {
    $failed_query .= " AND DATE(created_at) >= '$date_from'";
}
if ($date_to) {
    $failed_query .= " AND DATE(created_at) <= '$date_to'";
}
$failed_query .= " ORDER BY created_at DESC LIMIT 500";
$failed_logs = $conn->query($failed_query);

// Get blocked IPs
$blocked_query = "SELECT * FROM blocked_ips WHERE 1=1";
if ($search) {
    $blocked_query .= " AND ip_address LIKE '%$search%'";
}
if ($date_from) {
    $blocked_query .= " AND DATE(created_at) >= '$date_from'";
}
if ($date_to) {
    $blocked_query .= " AND DATE(created_at) <= '$date_to'";
}
$blocked_query .= " ORDER BY created_at DESC";
$blocked_ips = $conn->query($blocked_query);

// Get statistics
$stats = [];
$result = $conn->query("SELECT COUNT(*) as total FROM intrusion_logs");
$stats['total_intrusions'] = $result->fetch_assoc()['total'];

$result = $conn->query("SELECT COUNT(*) as total FROM intrusion_logs WHERE threat_level = 'Critical'");
$stats['critical'] = $result->fetch_assoc()['total'];

$result = $conn->query("SELECT COUNT(*) as total FROM intrusion_logs WHERE threat_level = 'High'");
$stats['high'] = $result->fetch_assoc()['total'];

$result = $conn->query("SELECT COUNT(*) as total FROM intrusion_logs WHERE threat_level = 'Medium'");
$stats['medium'] = $result->fetch_assoc()['total'];

$result = $conn->query("SELECT COUNT(*) as total FROM intrusion_logs WHERE threat_level = 'Low'");
$stats['low'] = $result->fetch_assoc()['total'];

$result = $conn->query("SELECT COUNT(*) as total FROM failed_logins");
$stats['failed_logins'] = $result->fetch_assoc()['total'];

$result = $conn->query("SELECT COUNT(*) as total FROM blocked_ips WHERE expires_at > NOW() OR expires_at IS NULL");
$stats['active_blocks'] = $result->fetch_assoc()['total'];

// Get today's stats
$result = $conn->query("SELECT COUNT(*) as total FROM intrusion_logs WHERE DATE(created_at) = CURDATE()");
$stats['today_intrusions'] = $result->fetch_assoc()['total'];

$result = $conn->query("SELECT COUNT(*) as total FROM failed_logins WHERE DATE(created_at) = CURDATE()");
$stats['today_failed'] = $result->fetch_assoc()['total'];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logs Management - MOHAZ BANK IDPS</title>
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
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #334155;
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: #1e293b;
            padding: 15px;
            border-radius: 10px;
            text-align: center;
        }
        
        .stat-number {
            font-size: 28px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-label {
            color: #94a3b8;
            font-size: 12px;
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
        
        .nav {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }
        
        .nav a {
            color: #38bdf8;
            text-decoration: none;
            padding: 8px 16px;
            background: #334155;
            border-radius: 5px;
            transition: background 0.3s;
        }
        
        .nav a:hover {
            background: #475569;
        }
        
        .nav a.active {
            background: #22c55e;
            color: white;
        }
        
        .logout-btn {
            background: #dc2626 !important;
            color: white !important;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #334155;
        }
        
        th {
            background: #334155;
            color: #38bdf8;
            position: sticky;
            top: 0;
        }
        
        tr:hover {
            background: #2d3748;
        }
        
        .critical {
            color: #dc2626;
            font-weight: bold;
        }
        
        .high {
            color: #f87171;
        }
        
        .medium {
            color: #fbbf24;
        }
        
        .low {
            color: #4ade80;
        }
        
        .filter-bar {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            margin-bottom: 20px;
            align-items: center;
        }
        
        .filter-bar input, .filter-bar select {
            padding: 8px 12px;
            background: #0f172a;
            border: 1px solid #334155;
            color: white;
            border-radius: 5px;
        }
        
        .filter-bar button {
            background: #3b82f6;
            color: white;
            padding: 8px 16px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        
        .btn-danger {
            background: #dc2626;
        }
        
        .btn-warning {
            background: #f59e0b;
        }
        
        .btn-success {
            background: #22c55e;
        }
        
        .table-responsive {
            overflow-x: auto;
            max-height: 500px;
            overflow-y: auto;
        }
        
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 1px solid #334155;
            padding-bottom: 10px;
        }
        
        .tab {
            padding: 10px 20px;
            background: #334155;
            border-radius: 5px;
            cursor: pointer;
            transition: background 0.3s;
        }
        
        .tab.active {
            background: #22c55e;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .action-buttons {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        
        .ip-badge {
            font-family: monospace;
            background: #0f172a;
            padding: 4px 8px;
            border-radius: 4px;
        }
        
        @media (max-width: 768px) {
            .header {
                flex-direction: column;
                text-align: center;
            }
            
            th, td {
                padding: 8px;
                font-size: 12px;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>📋 Logs Management</h1>
                <p style="color: #94a3b8;">Security Audit & Intrusion Detection Logs</p>
            </div>
          <div class="sidebar-menu">
    <a href="dashboard.php">📊 <span> Dashboard</span></a>
    <a href="customers.php">👤 <span> My Customers</span></a>
    <a href="view_all_customers.php">👑 <span> All Customers</span></a>
    <a href="users.php">👥 <span> Manage Users</span></a>
    <a href="logs.php" class="active">📋 <span> System Logs</span></a>
    <a href="../auth/logout.php">🚪 <span> Logout</span></a>
</div>
        </div>
        
        <!-- Statistics -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number" style="color: #38bdf8;"><?php echo $stats['total_intrusions']; ?></div>
                <div class="stat-label">Total Intrusions</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #dc2626;"><?php echo $stats['critical']; ?></div>
                <div class="stat-label">Critical Threats</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #f87171;"><?php echo $stats['high']; ?></div>
                <div class="stat-label">High Threats</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #fbbf24;"><?php echo $stats['medium']; ?></div>
                <div class="stat-label">Medium Threats</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #4ade80;"><?php echo $stats['low']; ?></div>
                <div class="stat-label">Low Threats</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #f97316;"><?php echo $stats['failed_logins']; ?></div>
                <div class="stat-label">Failed Logins</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #a855f7;"><?php echo $stats['active_blocks']; ?></div>
                <div class="stat-label">Active Blocks</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #06b6d4;"><?php echo $stats['today_intrusions']; ?></div>
                <div class="stat-label">Today's Intrusions</div>
            </div>
        </div>
        
        <!-- Filter Bar -->
        <div class="card">
            <h2>🔍 Filter Logs</h2>
            <form method="GET" action="" class="filter-bar">
                <select name="filter">
                    <option value="all" <?php echo $filter_type == 'all' ? 'selected' : ''; ?>>All Threats</option>
                    <option value="Critical" <?php echo $filter_type == 'Critical' ? 'selected' : ''; ?>>Critical</option>
                    <option value="High" <?php echo $filter_type == 'High' ? 'selected' : ''; ?>>High</option>
                    <option value="Medium" <?php echo $filter_type == 'Medium' ? 'selected' : ''; ?>>Medium</option>
                    <option value="Low" <?php echo $filter_type == 'Low' ? 'selected' : ''; ?>>Low</option>
                </select>
                <input type="text" name="search" placeholder="Search IP or Activity..." value="<?php echo htmlspecialchars($search); ?>">
                <input type="date" name="date_from" placeholder="From Date" value="<?php echo $date_from; ?>">
                <input type="date" name="date_to" placeholder="To Date" value="<?php echo $date_to; ?>">
                <button type="submit">🔍 Apply Filter</button>
                <a href="logs.php" class="btn-warning" style="padding: 8px 16px; background: #f59e0b; color: white; text-decoration: none; border-radius: 5px;">Reset</a>
            </form>
        </div>
        
        <!-- Action Buttons -->
        <div class="card">
            <h2>⚙️ Log Actions</h2>
            <div class="action-buttons">
                <form method="POST" style="display: inline;" onsubmit="return confirm('Clear intrusion logs? This cannot be undone.');">
                    <input type="hidden" name="log_type" value="intrusion">
                    <button type="submit" name="clear_logs" class="btn-danger">🗑️ Clear Intrusion Logs</button>
                </form>
                <form method="POST" style="display: inline;" onsubmit="return confirm('Clear failed login logs? This cannot be undone.');">
                    <input type="hidden" name="log_type" value="failed">
                    <button type="submit" name="clear_logs" class="btn-danger">🗑️ Clear Failed Logins</button>
                </form>
                <form method="POST" style="display: inline;" onsubmit="return confirm('Clear blocked IPs? This cannot be undone.');">
                    <input type="hidden" name="log_type" value="blocked">
                    <button type="submit" name="clear_logs" class="btn-danger">🗑️ Clear Blocked IPs</button>
                </form>
                <form method="POST" style="display: inline;" onsubmit="return confirm('Clear ALL logs? This cannot be undone.');">
                    <input type="hidden" name="log_type" value="all">
                    <button type="submit" name="clear_logs" class="btn-danger" style="background: #991b1b;">⚠️ Clear All Logs</button>
                </form>
            </div>
            <div class="action-buttons" style="margin-top: 10px;">
                <form method="POST" style="display: inline;">
                    <input type="hidden" name="log_type" value="intrusion">
                    <button type="submit" name="export_logs" class="btn-success">📥 Export Intrusion Logs (CSV)</button>
                </form>
                <form method="POST" style="display: inline;">
                    <input type="hidden" name="log_type" value="failed">
                    <button type="submit" name="export_logs" class="btn-success">📥 Export Failed Logins (CSV)</button>
                </form>
                <form method="POST" style="display: inline;">
                    <input type="hidden" name="log_type" value="blocked">
                    <button type="submit" name="export_logs" class="btn-success">📥 Export Blocked IPs (CSV)</button>
                </form>
            </div>
        </div>
        
        <!-- Tabs for different log types -->
        <div class="card">
            <div class="tabs">
                <div class="tab active" onclick="showTab('intrusion')">🛡️ Intrusion Logs</div>
                <div class="tab" onclick="showTab('failed')">🔐 Failed Logins</div>
                <div class="tab" onclick="showTab('blocked')">🚫 Blocked IPs</div>
            </div>
            
            <!-- Intrusion Logs Tab -->
            <div id="intrusion-tab" class="tab-content active">
                <h2>🛡️ Intrusion Detection Logs</h2>
                <div class="table-responsive">
                    <?php if ($intrusion_logs && $intrusion_logs->num_rows > 0): ?>
                        <table>
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>IP Address</th>
                                    <th>Activity</th>
                                    <th>Threat Level</th>
                                    <th>Status</th>
                                    <th>Timestamp</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php while ($log = $intrusion_logs->fetch_assoc()): ?>
                                <tr>
                                    <td><?php echo $log['id']; ?></td>
                                    <td><code class="ip-badge"><?php echo htmlspecialchars($log['ip_address']); ?></code></td>
                                    <td><?php echo htmlspecialchars(substr($log['activity'], 0, 100)); ?></td>
                                    <td class="<?php echo strtolower($log['threat_level']); ?>">
                                        <?php echo $log['threat_level']; ?>
                                    </td>
                                    <td><?php echo $log['status']; ?></td>
                                    <td><?php echo date('Y-m-d H:i:s', strtotime($log['created_at'])); ?></td>
                                </tr>
                                <?php endwhile; ?>
                            </tbody>
                        </table>
                    <?php else: ?>
                        <p style="text-align: center; padding: 40px;">✅ No intrusion logs found.</p>
                    <?php endif; ?>
                </div>
            </div>
            
            <!-- Failed Logins Tab -->
            <div id="failed-tab" class="tab-content">
                <h2>🔐 Failed Login Attempts</h2>
                <div class="table-responsive">
                    <?php if ($failed_logs && $failed_logs->num_rows > 0): ?>
                        <table>
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>IP Address</th>
                                    <th>Username</th>
                                    <th>User Agent</th>
                                    <th>Timestamp</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php while ($log = $failed_logs->fetch_assoc()): ?>
                                <tr>
                                    <td><?php echo $log['id']; ?></td>
                                    <td><code class="ip-badge"><?php echo htmlspecialchars($log['ip_address']); ?></code></td>
                                    <td><?php echo htmlspecialchars($log['username'] ?: 'Unknown'); ?></td>
                                    <td><?php echo htmlspecialchars(substr($log['user_agent'], 0, 50)); ?>...</td>
                                    <td><?php echo date('Y-m-d H:i:s', strtotime($log['created_at'])); ?></td>
                                </tr>
                                <?php endwhile; ?>
                            </tbody>
                        </table>
                    <?php else: ?>
                        <p style="text-align: center; padding: 40px;">✅ No failed login attempts recorded.</p>
                    <?php endif; ?>
                </div>
            </div>
            
            <!-- Blocked IPs Tab -->
            <div id="blocked-tab" class="tab-content">
                <h2>🚫 Blocked IP Addresses</h2>
                <div class="table-responsive">
                    <?php if ($blocked_ips && $blocked_ips->num_rows > 0): ?>
                        <table>
                            <thead>
                                65;5m
                                    <th>ID</th>
                                    <th>IP Address</th>
                                    <th>Expires At</th>
                                    <th>Blocked Since</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php while ($ip = $blocked_ips->fetch_assoc()): ?>
                                <tr>
                                    <td><?php echo $ip['id']; ?></td>
                                    <td><code class="ip-badge"><?php echo htmlspecialchars($ip['ip_address']); ?></code></td>
                                    <td><?php echo $ip['expires_at'] ? date('Y-m-d H:i:s', strtotime($ip['expires_at'])) : 'Permanent'; ?></td>
                                    <td><?php echo date('Y-m-d H:i:s', strtotime($ip['created_at'])); ?></td>
                                    <td>
                                        <?php if (!$ip['expires_at'] || strtotime($ip['expires_at']) > time()): ?>
                                            <span style="color: #dc2626;">🔴 Blocked</span>
                                        <?php else: ?>
                                            <span style="color: #4ade80;">🟢 Expired</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                                <?php endwhile; ?>
                            </tbody>
                        </table>
                    <?php else: ?>
                        <p style="text-align: center; padding: 40px;">✅ No IPs are currently blocked.</p>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        
        <!-- Log Retention Info -->
        <div class="card">
            <h2>ℹ️ Log Information</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px;">
                <div>
                    <strong>📊 Intrusion Logs:</strong> <?php echo $stats['total_intrusions']; ?> records<br>
                    <small>Records all suspicious activities and security threats</small>
                </div>
                <div>
                    <strong>🔐 Failed Logins:</strong> <?php echo $stats['failed_logins']; ?> records<br>
                    <small>Tracks all failed login attempts (helps detect brute force)</small>
                </div>
                <div>
                    <strong>🚫 Blocked IPs:</strong> <?php echo $stats['active_blocks']; ?> active<br>
                    <small>IPs automatically blocked due to suspicious activity</small>
                </div>
                <div>
                    <strong>📅 Retention:</strong> Unlimited<br>
                    <small>Logs are kept indefinitely for audit purposes</small>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function showTab(tabName) {
            // Hide all tabs
            document.getElementById('intrusion-tab').classList.remove('active');
            document.getElementById('failed-tab').classList.remove('active');
            document.getElementById('blocked-tab').classList.remove('active');
            
            // Remove active class from all tab buttons
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName + '-tab').classList.add('active');
            
            // Add active class to clicked tab
            event.target.classList.add('active');
        }
        
        // Auto-refresh logs every 30 seconds (optional)
        // setInterval(function() {
        //     location.reload();
        // }, 30000);
    </script>
</body>
</html>