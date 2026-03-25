<?php
/**
 * MOHAZ BANK Database Configuration
 * Intrusion Detection & Prevention System
 */

// Define constants only if they haven't been defined yet
if (!defined('DB_HOST')) {
    define('DB_HOST', 'localhost');
}
if (!defined('DB_USER')) {
    define('DB_USER', 'root');
}
if (!defined('DB_PASS')) {
    define('DB_PASS', '');
}
if (!defined('DB_NAME')) {
    define('DB_NAME', 'mohaz_bank');
}

// Error reporting (disable in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Create connection
try {
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    // Check connection
    if ($conn->connect_error) {
        throw new Exception("Connection failed: " . $conn->connect_error);
    }
    
    // Set charset to UTF-8
    $conn->set_charset("utf8mb4");
    
    // Include encryption helper
    $encryption_file = __DIR__ . '/encryption.php';
    if (file_exists($encryption_file)) {
        require_once($encryption_file);
        if (class_exists('EncryptionHelper')) {
            $encryption = new EncryptionHelper();
        }
    }
    
} catch (Exception $e) {
    // Log error
    error_log("Database connection error: " . $e->getMessage());
    
    // Only show error in development
    if (isset($_SERVER['HTTP_HOST']) && $_SERVER['HTTP_HOST'] == 'localhost') {
        die("Database connection failed: " . $e->getMessage());
    } else {
        die("System temporarily unavailable. Please try again later.");
    }
}
?>