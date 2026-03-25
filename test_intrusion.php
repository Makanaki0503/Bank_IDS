<?php
echo "<h1>Intrusion Detection Test</h1>";

// Test patterns
$tests = [
    "SQL Injection" => "?id=1' OR '1'='1",
    "XSS Attack" => "?q=<script>alert(1)</script>",
    "Path Traversal" => "?file=../../etc/passwd",
    "Command Injection" => "?cmd=whoami",
    "Normal Request" => ""
];

foreach ($tests as $name => $query) {
    echo "<p><strong>Testing: $name</strong><br>";
    echo "URL: <code>http://localhost/mohaz_bank/$query</code><br>";
    echo "<a href='http://localhost/mohaz_bank/$query' target='_blank'>Test Now</a></p>";
    echo "<hr>";
}

// Check logs
include("config/db.php");
$result = $conn->query("SELECT COUNT(*) as total FROM intrusion_logs");
$row = $result->fetch_assoc();
echo "<h2>Intrusion Logs Count: " . $row['total'] . "</h2>";

$result = $conn->query("SELECT * FROM intrusion_logs ORDER BY id DESC LIMIT 5");
if ($result->num_rows > 0) {
    echo "<h3>Recent Intrusions:</h3>";
    echo "<table border='1' cellpadding='5' style='border-collapse: collapse;'>";
    echo "<tr><th>IP</th><th>Activity</th><th>Threat Level</th><th>Time</th></tr>";
    while ($row = $result->fetch_assoc()) {
        echo "<tr>";
        echo "<td>" . htmlspecialchars($row['ip_address']) . "</td>";
        echo "<td>" . htmlspecialchars(substr($row['activity'], 0, 50)) . "</td>";
        echo "<td style='color: " . ($row['threat_level'] == 'Critical' ? '#dc2626' : '#fbbf24') . "'>" . $row['threat_level'] . "</td>";
        echo "<td>" . $row['created_at'] . "</td>";
        echo "</tr>";
    }
    echo "</table>";
}
?>