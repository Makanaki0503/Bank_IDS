<?php
/**
 * MOHAZ BANK Intrusion Detection & Prevention System
 * Real-time threat detection and response
 */

// Include database configuration safely
$config_file = __DIR__ . "/../config/db.php";
if (file_exists($config_file)) {
    require_once($config_file); // Use require_once instead of include
} else {
    error_log("Database configuration not found");
    return;
}

// Ensure database connection exists
if (!isset($conn) || !$conn) {
    error_log("Database connection not available for intrusion detection");
    return;
}

// Get request information
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$activity = $_SERVER['REQUEST_URI'] ?? '';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
$query_string = $_SERVER['QUERY_STRING'] ?? '';
$full_url = (isset($_SERVER['HTTPS']) ? "https://" : "http://") . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

// Skip detection for certain paths (whitelist)
$skip_paths = [
    '/assets/', '/css/', '/js/', '/images/', '/favicon.ico',
    '/robots.txt', '/auth/login.php', '/auth/register.php',
    '/test_db.php', '/setup_database.php', '/create_admin.php',
    '/test_intrusion.php', '/admin/dashboard.php', '/admin/users.php', 
    '/admin/customers.php', '/admin/logs.php'
];

foreach ($skip_paths as $path) {
    if (strpos($activity, $path) !== false) {
        return; // Skip detection for these paths
    }
}

// ============================================
// THREAT DETECTION PATTERNS
// ============================================

$threat_level = 'Low';
$matched_pattern = '';
$is_threat = false;

// Critical threats - Immediate blocking
$critical_patterns = [
    // SQL Injection
    '/select.*from.*information_schema/i',
    '/union.*select.*password/i',
    '/union.*select.*username/i',
    '/drop\s+table/i',
    '/drop\s+database/i',
    '/insert\s+into.*values/i',
    '/update.*set.*=/i',
    '/delete\s+from/i',
    '/\bOR\s+1\s*=\s*1\b/i',
    '/\bOR\s+1=1/i',
    '/\bAND\s+1=1/i',
    '/;.*--/',
    '/\/\*.*\*\//',
    '/\bUNION\b.*\bSELECT\b/i',
    '/\bSELECT\b.*\bFROM\b/i',
    '/\bWHERE\b.*\b=\b.*\bOR\b/i',
    
    // XSS Attacks
    '/<script.*?>.*?<\/script>/is',
    '/javascript:/i',
    '/onload\s*=/i',
    '/onclick\s*=/i',
    '/onerror\s*=/i',
    '/alert\s*\(/i',
    '/prompt\s*\(/i',
    '/confirm\s*\(/i',
    '/document\.cookie/i',
    '/window\.location/i',
    '/eval\s*\(/i',
    
    // Path Traversal
    '/\.\.\/|\.\.\\\/',
    '/\/etc\/passwd/i',
    '/\/etc\/shadow/i',
    '/boot\.ini/i',
    '/windows\/win\.ini/i',
    
    // Command Injection
    '/\bexec\b/i',
    '/\bsystem\b/i',
    '/\bpassthru\b/i',
    '/\bshell_exec\b/i',
    '/\beval\b/i',
    '/\bcmd\b/i',
    '/\bpowershell\b/i',
    '/\bwget\b/i',
    '/\bcurl\b/i',
    '/\bnc\s/i',
    '/\bnet\s+user/i',
    '/\bwhoami\b/i',
];

// Check critical patterns
foreach ($critical_patterns as $pattern) {
    if (preg_match($pattern, $activity) || preg_match($pattern, $query_string)) {
        $threat_level = 'Critical';
        $matched_pattern = $pattern;
        $is_threat = true;
        break;
    }
}

// High severity threats if not already critical
if (!$is_threat) {
    $high_patterns = [
        '/select.*from/i',
        '/union.*select/i',
        '/insert.*into/i',
        '/update.*set/i',
        '/delete.*from/i',
        '/script/i',
        '/iframe/i',
        '/\.\.\//',
        '/\.\.\\\\/',
        '/phpinfo/i',
        '/ini_set/i',
    ];
    
    foreach ($high_patterns as $pattern) {
        if (preg_match($pattern, $activity) || preg_match($pattern, $query_string)) {
            $threat_level = 'High';
            $matched_pattern = $pattern;
            $is_threat = true;
            break;
        }
    }
}

// Medium severity threats if not already detected
if (!$is_threat) {
    $medium_patterns = [
        '/sqlmap/i', '/nmap/i', '/nikto/i', '/dirbuster/i', 
        '/wpscan/i', '/burpsuite/i', '/python-requests/i', '/curl/i', '/wget/i'
    ];
    
    foreach ($medium_patterns as $pattern) {
        if (preg_match($pattern, $activity) || preg_match($pattern, $user_agent)) {
            $threat_level = 'Medium';
            $matched_pattern = $pattern;
            $is_threat = true;
            break;
        }
    }
}

// ============================================
// THREAT RESPONSE - LOG AND BLOCK
// ============================================

if ($is_threat) {
    try {
        // Ensure tables exist
        @$conn->query("CREATE TABLE IF NOT EXISTS intrusion_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45),
            activity TEXT,
            threat_level VARCHAR(20),
            status VARCHAR(50),
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )");
        
        @$conn->query("CREATE TABLE IF NOT EXISTS blocked_ips (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) UNIQUE,
            expires_at TIMESTAMP NULL,
            reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )");
        
        // Prepare log details
        $details = json_encode([
            'method' => $method,
            'uri' => $activity,
            'query' => $query_string,
            'user_agent' => $user_agent,
            'matched_pattern' => $matched_pattern,
            'full_url' => $full_url
        ]);
        
        // Log the intrusion
        $status = $threat_level == 'Critical' ? 'Blocked' : 'Detected';
        $stmt = $conn->prepare("INSERT INTO intrusion_logs (ip_address, activity, threat_level, status, details) VALUES (?, ?, ?, ?, ?)");
        if ($stmt) {
            $stmt->bind_param("sssss", $ip, $activity, $threat_level, $status, $details);
            $stmt->execute();
            $stmt->close();
            
            // Echo debug comment (visible in source)
            echo "<!-- Intrusion detected: $threat_level level at " . date('Y-m-d H:i:s') . " -->\n";
        }
        
        // Check for repeated violations
        $stmt = $conn->prepare("SELECT COUNT(*) as attempts FROM intrusion_logs 
                               WHERE ip_address = ? AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)");
        if ($stmt) {
            $stmt->bind_param("s", $ip);
            $stmt->execute();
            $result = $stmt->get_result();
            $attempts = 0;
            if ($result && $row = $result->fetch_assoc()) {
                $attempts = $row['attempts'];
            }
            $stmt->close();
        } else {
            $attempts = 1;
        }
        
        // Block IP for repeated violations or critical threats
        if ($attempts >= 3 || $threat_level == 'Critical') {
            $block_reason = $threat_level == 'Critical' ? 'Critical threat detected: ' . $matched_pattern : 'Multiple violations (' . $attempts . ' attempts)';
            $block_stmt = $conn->prepare("INSERT INTO blocked_ips (ip_address, expires_at, reason) 
                                          VALUES (?, DATE_ADD(NOW(), INTERVAL 24 HOUR), ?)
                                          ON DUPLICATE KEY UPDATE expires_at = DATE_ADD(NOW(), INTERVAL 24 HOUR), reason = ?");
            if ($block_stmt) {
                $block_stmt->bind_param("sss", $ip, $block_reason, $block_reason);
                $block_stmt->execute();
                $block_stmt->close();
            }
            
            // Log to file
            $log_dir = __DIR__ . "/../logs/";
            if (!file_exists($log_dir)) {
                @mkdir($log_dir, 0755, true);
            }
            
            $log_entry = date('Y-m-d H:i:s') . " | BLOCKED | IP: $ip | Threat: $threat_level | Pattern: $matched_pattern | Activity: $activity\n";
            @file_put_contents($log_dir . "intrusions.log", $log_entry, FILE_APPEND);
            
            // Show block page for critical threats
            if ($threat_level == 'Critical') {
                http_response_code(403);
                die('<!DOCTYPE html>
                <html>
                <head><title>Access Denied</title>
                <style>
                    body { font-family: Arial; background: #0f172a; color: white; text-align: center; padding: 50px; }
                    .container { max-width: 500px; margin: 0 auto; background: #1e293b; padding: 30px; border-radius: 10px; }
                    h1 { color: #dc2626; }
                    .ip { background: #0f172a; padding: 10px; border-radius: 5px; margin: 20px 0; font-family: monospace; }
                </style>
                </head>
                <body>
                <div class="container">
                    <h1>🚫 ACCESS DENIED</h1>
                    <p>Suspicious activity detected by Intrusion Detection System.</p>
                    <div class="ip">Your IP: ' . htmlspecialchars($ip) . '<br>Threat Level: <span style="color:#dc2626;">' . $threat_level . '</span></div>
                    <p>This incident has been logged.</p>
                </div>
                </body>
                </html>');
            }
        }
        
        // Add delay for high threats
        if ($threat_level == 'High') {
            usleep(300000); // 0.3 second delay
        }
        
    } catch (Exception $e) {
        error_log("IDPS Error: " . $e->getMessage());
    }
}

// ============================================
// CHECK IF IP IS ALREADY BLOCKED
// ============================================

try {
    $stmt = $conn->prepare("SELECT id, reason, expires_at FROM blocked_ips 
                            WHERE ip_address = ? AND (expires_at IS NULL OR expires_at > NOW())");
    if ($stmt) {
        $stmt->bind_param("s", $ip);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result && $result->num_rows > 0) {
            $block = $result->fetch_assoc();
            http_response_code(403);
            die('<!DOCTYPE html>
            <html>
            <head><title>IP Blocked</title>
            <style>
                body { font-family: Arial; background: #0f172a; color: white; text-align: center; padding: 50px; }
                .container { max-width: 500px; margin: 0 auto; background: #1e293b; padding: 30px; border-radius: 10px; }
                h1 { color: #dc2626; }
            </style>
            </head>
            <body>
            <div class="container">
                <h1>🔒 IP BLOCKED</h1>
                <p>Your IP address has been temporarily blocked due to suspicious activity.</p>
                <p>Reason: ' . htmlspecialchars($block['reason']) . '</p>
                <p>' . ($block['expires_at'] ? 'Expires: ' . date('Y-m-d H:i:s', strtotime($block['expires_at'])) : 'Permanent Block') . '</p>
            </div>
            </body>
            </html>');
        }
        $stmt->close();
    }
} catch (Exception $e) {
    error_log("IP block check failed: " . $e->getMessage());
}

// Add security headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
?>