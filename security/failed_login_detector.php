<?php
class FailedLoginDetector {
    private $conn;
    private $max_attempts = 5;
    private $lockout_minutes = 15;
    
    public function __construct($database_connection) {
        $this->conn = $database_connection;
    }
    
    public function recordFailedAttempt($username, $ip) {
        $stmt = $this->conn->prepare("INSERT INTO failed_logins (ip_address, username) VALUES (?, ?)");
        $stmt->bind_param("ss", $ip, $username);
        $stmt->execute();
        
        return $this->getRemainingAttempts($username);
    }
    
    public function getRemainingAttempts($username) {
        $stmt = $this->conn->prepare("SELECT COUNT(*) as attempts FROM failed_logins WHERE username = ? AND created_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        
        return max(0, $this->max_attempts - $row['attempts']);
    }
    
    public function resetAttempts($username) {
        $stmt = $this->conn->prepare("DELETE FROM failed_logins WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
    }
    
    public function isIPBlocked($ip) {
        $stmt = $this->conn->prepare("SELECT id FROM blocked_ips WHERE ip_address = ? AND (expires_at IS NULL OR expires_at > NOW())");
        $stmt->bind_param("s", $ip);
        $stmt->execute();
        $result = $stmt->get_result();
        return $result->num_rows > 0;
    }
}
?>