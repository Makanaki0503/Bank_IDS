<?php
session_start();
include(__DIR__ . "/../config/db.php");
include(__DIR__ . "/../includes/check_role.php");

// Only admin can access this page
requireAdmin();

$message = '';
$decrypted_customers = [];
$admin_username = getUsername();
$user_ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

// Get admin's encryption key
$stmt = $conn->prepare("SELECT encryption_key FROM users WHERE username = ?");
$stmt->bind_param("s", $admin_username);
$stmt->execute();
$result = $stmt->get_result();
$admin = $result->fetch_assoc();
$admin_key = $admin['encryption_key'] ?? '';
$stmt->close();

// Search and filter variables
$search = isset($_GET['search']) ? trim($_GET['search']) : '';
$filter_by = isset($_GET['filter_by']) ? $_GET['filter_by'] : 'all';
$sort_by = isset($_GET['sort_by']) ? $_GET['sort_by'] : 'created_at';
$sort_order = isset($_GET['sort_order']) ? $_GET['sort_order'] : 'DESC';

// Build query
$query = "SELECT * FROM customers WHERE 1=1";

if (!empty($search)) {
    $query .= " AND (customer_id LIKE '%$search%' OR created_by LIKE '%$search%')";
}

if ($filter_by !== 'all') {
    $query .= " AND created_by = '$filter_by'";
}

$query .= " ORDER BY $sort_by $sort_order";

// Get all customers
$customers = $conn->query($query);

if ($customers && $customers->num_rows > 0) {
    $decrypt_success_admin = 0;
    $decrypt_success_user = 0;
    $decrypt_failed = 0;
    
    while ($row = $customers->fetch_assoc()) {
        try {
            $iv = $row['iv'] ?? '';
            $stored_key = $row['user_key'] ?? '';
            
            if (empty($iv)) {
                $row['decrypted_name'] = 'ERROR: Missing IV';
                $row['decrypted_email'] = 'ERROR: Missing IV';
                $row['decrypted_phone'] = 'ERROR: Missing IV';
                $row['decrypted_account'] = 'ERROR: Missing IV';
                $row['decrypted_balance'] = '0';
                $row['decrypt_status'] = 'failed';
                $decrypt_failed++;
            } else {
                // Try to decrypt with admin key first
                $decrypted_name = $encryption->decrypt($row['encrypted_name'], $admin_key, $iv);
                
                if ($decrypted_name !== false && $decrypted_name !== null && $decrypted_name !== '') {
                    // Decrypted successfully with admin key
                    $row['decrypted_name'] = $decrypted_name;
                    $row['decrypted_email'] = $encryption->decrypt($row['encrypted_email'], $admin_key, $iv);
                    $row['decrypted_phone'] = $encryption->decrypt($row['encrypted_phone'], $admin_key, $iv);
                    $row['decrypted_account'] = $encryption->decrypt($row['encrypted_account_number'], $admin_key, $iv);
                    $row['decrypted_balance'] = $encryption->decrypt($row['encrypted_balance'], $admin_key, $iv);
                    $row['decrypt_status'] = 'success_admin';
                    $decrypt_success_admin++;
                } else {
                    // Try with original user key
                    $decrypted_name = $encryption->decrypt($row['encrypted_name'], $stored_key, $iv);
                    
                    if ($decrypted_name !== false && $decrypted_name !== null && $decrypted_name !== '') {
                        $row['decrypted_name'] = $decrypted_name;
                        $row['decrypted_email'] = $encryption->decrypt($row['encrypted_email'], $stored_key, $iv);
                        $row['decrypted_phone'] = $encryption->decrypt($row['encrypted_phone'], $stored_key, $iv);
                        $row['decrypted_account'] = $encryption->decrypt($row['encrypted_account_number'], $stored_key, $iv);
                        $row['decrypted_balance'] = $encryption->decrypt($row['encrypted_balance'], $stored_key, $iv);
                        $row['decrypt_status'] = 'success_user';
                        $decrypt_success_user++;
                    } else {
                        $row['decrypted_name'] = 'Decryption Failed';
                        $row['decrypted_email'] = 'Decryption Failed';
                        $row['decrypted_phone'] = 'Decryption Failed';
                        $row['decrypted_account'] = 'Decryption Failed';
                        $row['decrypted_balance'] = '0';
                        $row['decrypt_status'] = 'failed';
                        $decrypt_failed++;
                    }
                }
            }
            
            $row['created_by'] = $row['created_by'] ?? 'Unknown';
            $decrypted_customers[] = $row;
            
        } catch (Exception $e) {
            $row['decrypted_name'] = 'Error: ' . $e->getMessage();
            $row['decrypted_email'] = 'Error: ' . $e->getMessage();
            $row['decrypted_phone'] = 'Error: ' . $e->getMessage();
            $row['decrypted_account'] = 'Error: ' . $e->getMessage();
            $row['decrypted_balance'] = '0';
            $row['created_by'] = $row['created_by'] ?? 'Unknown';
            $row['decrypt_status'] = 'failed';
            $decrypted_customers[] = $row;
            $decrypt_failed++;
        }
    }
    
    $message = "✅ Found " . count($decrypted_customers) . " customer(s).";
}

// Get statistics
$total_customers = $conn->query("SELECT COUNT(*) as total FROM customers")->fetch_assoc()['total'];

// Get unique creators for filter
$creators = [];
$result = $conn->query("SELECT DISTINCT created_by FROM customers WHERE created_by IS NOT NULL");
if ($result) {
    while ($row = $result->fetch_assoc()) {
        $creators[] = $row['created_by'];
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin - All Customers - MOHAZ BANK</title>
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
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: #1e293b;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        
        .stat-number {
            font-size: 28px;
            font-weight: bold;
            margin-bottom: 8px;
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
        
        .key-box {
            background: #0f172a;
            padding: 15px;
            border-radius: 8px;
            font-family: monospace;
            word-break: break-all;
            margin: 10px 0;
        }
        
        .filter-bar {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            margin-bottom: 20px;
            align-items: flex-end;
        }
        
        .filter-bar .form-group {
            margin-bottom: 0;
            flex: 1;
            min-width: 150px;
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
        
        .btn-danger {
            background: #dc2626;
            color: white;
        }
        
        .btn-danger:hover {
            background: #b91c1c;
        }
        
        .btn-success {
            background: #22c55e;
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
            cursor: pointer;
        }
        
        th:hover {
            background: #475569;
        }
        
        tr:hover {
            background: #2d3748;
        }
        
        .balance-positive {
            color: #4ade80;
            font-weight: bold;
        }
        
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: bold;
            margin-left: 5px;
        }
        
        .badge-admin {
            background: #3b82f6;
            color: white;
        }
        
        .badge-user {
            background: #f59e0b;
            color: white;
        }
        
        .badge-failed {
            background: #dc2626;
            color: white;
        }
        
        .table-responsive {
            overflow-x: auto;
            margin-top: 20px;
        }
        
        .message {
            background: #22c55e;
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
            th, td {
                padding: 8px;
                font-size: 12px;
            }
            .filter-bar {
                flex-direction: column;
            }
            .filter-bar .form-group {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="sidebar-header">
            <h2>👑</h2>
            <h3>MOHAZ BANK</h3>
        </div>
        <div class="sidebar-menu">
            <a href="dashboard.php">📊 <span> Dashboard</span></a>
            <a href="customers.php">👤 <span> My Customers</span></a>
            <a href="view_all_customers.php" class="active">👑 <span> All Customers</span></a>
            <a href="users.php">👥 <span> Manage Users</span></a>
            <a href="logs.php">📋 <span> System Logs</span></a>
            <a href="../auth/logout.php">🚪 <span> Logout</span></a>
        </div>
    </div>
    
    <div class="main-content">
        <div class="top-header">
            <div>
                <h1>👑 Admin - All Customer Records</h1>
                <p style="color: #94a3b8;">Full system view - View all customers in the database</p>
            </div>
            <div>
                <a href="dashboard.php" class="btn btn-primary">📊 Dashboard</a>
                <a href="customers.php" class="btn btn-primary">👤 My Customers</a>
                <a href="../auth/logout.php" class="btn btn-danger">🚪 Logout</a>
            </div>
        </div>
        
        <!-- Admin Key -->
        <div class="card">
            <h2>🔑 Admin Encryption Key</h2>
            <div class="key-box" id="adminKey"><?php echo htmlspecialchars($admin_key); ?></div>
            <button class="btn btn-primary" onclick="copyKey()">📋 Copy Key</button>
            <div class="warning" style="margin-top: 10px;">
                ⚠️ Admin key can decrypt ALL customers in the system. Keep this key secure!
            </div>
        </div>
        
        <!-- Statistics -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number" style="color: #38bdf8;"><?php echo $total_customers; ?></div>
                <div class="stat-label">Total Customers</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #4ade80;"><?php echo isset($decrypt_success_admin) ? $decrypt_success_admin : 0; ?></div>
                <div class="stat-label">Decrypted (Admin Key)</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #fbbf24;"><?php echo isset($decrypt_success_user) ? $decrypt_success_user : 0; ?></div>
                <div class="stat-label">Decrypted (User Key)</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #f87171;"><?php echo isset($decrypt_failed) ? $decrypt_failed : 0; ?></div>
                <div class="stat-label">Decryption Failed</div>
            </div>
        </div>
        
        <?php if ($message): ?>
            <div class="message">✅ <?php echo $message; ?></div>
        <?php endif; ?>
        
        <!-- Search and Filter Bar -->
        <div class="card">
            <h2>🔍 Filter Customers</h2>
            <form method="GET" action="" class="filter-bar">
                <div class="form-group">
                    <label>🔍 Search</label>
                    <input type="text" name="search" placeholder="Search by Customer ID or Creator..." value="<?php echo htmlspecialchars($search); ?>">
                </div>
                <div class="form-group">
                    <label>👤 Filter by Creator</label>
                    <select name="filter_by">
                        <option value="all">All Users</option>
                        <?php foreach ($creators as $creator): ?>
                            <option value="<?php echo htmlspecialchars($creator); ?>" <?php echo $filter_by == $creator ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($creator); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group">
                    <label>📊 Sort By</label>
                    <select name="sort_by">
                        <option value="created_at" <?php echo $sort_by == 'created_at' ? 'selected' : ''; ?>>Created Date</option>
                        <option value="customer_id" <?php echo $sort_by == 'customer_id' ? 'selected' : ''; ?>>Customer ID</option>
                        <option value="created_by" <?php echo $sort_by == 'created_by' ? 'selected' : ''; ?>>Created By</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>📈 Order</label>
                    <select name="sort_order">
                        <option value="DESC" <?php echo $sort_order == 'DESC' ? 'selected' : ''; ?>>Newest First</option>
                        <option value="ASC" <?php echo $sort_order == 'ASC' ? 'selected' : ''; ?>>Oldest First</option>
                    </select>
                </div>
                <button type="submit" class="btn btn-primary">Apply Filters</button>
                <a href="view_all_customers.php" class="btn btn-warning">Reset</a>
            </form>
        </div>
        
        <!-- Customers Table -->
        <div class="card">
            <h2>📋 All Customer Records</h2>
            <div class="table-responsive">
                <?php if (count($decrypted_customers) > 0): ?>
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
                                <th>Decrypt Status</th>
                                <th>Created Date</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($decrypted_customers as $c): ?>
                            <tr>
                                <td><code><?php echo htmlspecialchars($c['customer_id']); ?></code></td>
                                <td>
                                    <?php echo htmlspecialchars($c['decrypted_name']); ?>
                                    <?php if ($c['decrypt_status'] == 'success_admin'): ?>
                                        <span class="badge badge-admin">Admin</span>
                                    <?php elseif ($c['decrypt_status'] == 'success_user'): ?>
                                        <span class="badge badge-user">User</span>
                                    <?php else: ?>
                                        <span class="badge badge-failed">Failed</span>
                                    <?php endif; ?>
                                </td>
                                <td>📧 <?php echo htmlspecialchars($c['decrypted_email']); ?></td>
                                <td>📱 <?php echo htmlspecialchars($c['decrypted_phone']); ?></td>
                                <td>💳 <?php echo htmlspecialchars($c['decrypted_account']); ?></td>
                                <td class="balance-positive">₦ <?php echo number_format(floatval($c['decrypted_balance']), 2); ?></td>
                                <td><?php echo htmlspecialchars($c['created_by']); ?></td>
                                <td>
                                    <?php if ($c['decrypt_status'] == 'success_admin'): ?>
                                        <span style="color: #4ade80;">✅ Admin Key</span>
                                    <?php elseif ($c['decrypt_status'] == 'success_user'): ?>
                                        <span style="color: #fbbf24;">⚠️ User Key</span>
                                    <?php else: ?>
                                        <span style="color: #f87171;">❌ Failed</span>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo date('Y-m-d', strtotime($c['created_at'])); ?></td>
                                <td>
                                    <form method="POST" action="customers.php" style="display: inline;" onsubmit="return confirm('Delete this customer? This cannot be undone.');">
                                        <input type="hidden" name="customer_id" value="<?php echo $c['customer_id']; ?>">
                                        <button type="submit" name="delete_customer" class="btn btn-danger" style="padding: 4px 8px; font-size: 11px;">🗑️</button>
                                    </form>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    
                    <div style="margin-top: 15px; text-align: center; color: #94a3b8;">
                        Showing <?php echo count($decrypted_customers); ?> of <?php echo $total_customers; ?> total customers
                    </div>
                <?php else: ?>
                    <div style="text-align: center; padding: 60px 20px;">
                        <div style="font-size: 64px; margin-bottom: 20px;">📭</div>
                        <p>No customers found in the database.</p>
                        <p style="color: #94a3b8; margin-top: 10px;">Add customers through the customer management page.</p>
                    </div>
                <?php endif; ?>
            </div>
        </div>
        
        <!-- Legend -->
        <div class="card">
            <h2>📖 Decryption Status Legend</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px;">
                <div style="background: #0f172a; padding: 12px; border-radius: 8px;">
                    <span style="color: #4ade80;">✅ Admin Key</span><br>
                    <small>Decrypted successfully with admin key - Full visibility</small>
                </div>
                <div style="background: #0f172a; padding: 12px; border-radius: 8px;">
                    <span style="color: #fbbf24;">⚠️ User Key</span><br>
                    <small>Decrypted with original user key - Regular user would see this</small>
                </div>
                <div style="background: #0f172a; padding: 12px; border-radius: 8px;">
                    <span style="color: #f87171;">❌ Failed</span><br>
                    <small>Could not decrypt - Data may be corrupted or key mismatch</small>
                </div>
            </div>
        </div>
        
        <!-- Security Note -->
        <div class="card">
            <h2>🔒 Security Note</h2>
            <div class="warning" style="margin-bottom: 0;">
                <strong>Important:</strong> As an administrator, you have access to all customer records.<br>
                This page shows all customers in the system, regardless of which user created them.<br>
                Regular users only see customers they created on their own customer page.
            </div>
        </div>
    </div>
    
    <script>
        function copyKey() {
            const key = document.getElementById('adminKey').innerText;
            navigator.clipboard.writeText(key).then(() => {
                alert('Admin encryption key copied to clipboard!');
            });
        }
    </script>
</body>
</html>