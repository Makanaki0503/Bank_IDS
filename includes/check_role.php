<?php
/**
 * Role Check Helper - MOHAZ BANK IDPS
 * Check user permissions and redirect if unauthorized
 */

// Start session if not started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/**
 * Check if user is logged in
 */
function isLoggedIn() {
    return isset($_SESSION['user']) && isset($_SESSION['user_id']);
}

/**
 * Check if current user is admin
 */
function isAdmin() {
    return isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
}

/**
 * Check if current user is regular user
 */
function isUser() {
    return isset($_SESSION['role']) && $_SESSION['role'] === 'user';
}

/**
 * Require user to be logged in (redirect if not)
 */
function requireLogin() {
    if (!isLoggedIn()) {
        header("Location: ../auth/login.php");
        exit();
    }
}

/**
 * Require admin access (redirect if not admin)
 */
function requireAdmin() {
    requireLogin();
    if (!isAdmin()) {
        // Log unauthorized access attempt
        global $conn;
        if (isset($conn)) {
            $stmt = $conn->prepare("INSERT INTO intrusion_logs (ip_address, activity, threat_level, status) VALUES (?, ?, ?, ?)");
            $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
            $activity = "Unauthorized admin access attempt by user: " . $_SESSION['user'];
            $threat_level = "High";
            $status = "Blocked";
            $stmt->bind_param("ssss", $ip, $activity, $threat_level, $status);
            $stmt->execute();
        }
        
        // Redirect to dashboard with error
        $_SESSION['error'] = "Access denied. Admin privileges required.";
        header("Location: ../admin/dashboard.php");
        exit();
    }
}

/**
 * Require user access (redirect if not logged in)
 */
function requireUser() {
    requireLogin();
    // All logged-in users have user access
}

/**
 * Get user role
 */
function getUserRole() {
    return $_SESSION['role'] ?? 'guest';
}

/**
 * Get username
 */
function getUsername() {
    return $_SESSION['user'] ?? 'Guest';
}

/**
 * Get user ID
 */
function getUserId() {
    return $_SESSION['user_id'] ?? 0;
}

/**
 * Check if session is expired (30 minutes timeout)
 */
function isSessionExpired() {
    if (isset($_SESSION['login_time'])) {
        $timeout = 1800; // 30 minutes
        if (time() - $_SESSION['login_time'] > $timeout) {
            return true;
        }
    }
    return false;
}

/**
 * Check session and refresh if needed
 */
function checkSession() {
    if (isSessionExpired()) {
        session_destroy();
        header("Location: ../auth/login.php?timeout=1");
        exit();
    }
    // Refresh session time
    $_SESSION['login_time'] = time();
}
?>