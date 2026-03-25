<?php
// Include intrusion detection FIRST
include("security/detect.php");
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MOHAZ BANK - IDPS</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            text-align: center;
        }
        
        .container {
            background: rgba(30, 41, 59, 0.95);
            padding: 50px;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.3);
            max-width: 500px;
        }
        
        h1 {
            color: #38bdf8;
            font-size: 36px;
            margin-bottom: 10px;
        }
        
        .subtitle {
            color: #94a3b8;
            margin-bottom: 30px;
        }
        
        .btn {
            display: inline-block;
            padding: 12px 30px;
            margin: 10px;
            background: #22c55e;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            transition: background 0.3s;
        }
        
        .btn:hover {
            background: #16a34a;
        }
        
        .features {
            margin-top: 30px;
            text-align: left;
            color: #94a3b8;
            font-size: 12px;
        }
        
        .features li {
            margin: 5px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 MOHAZ BANK</h1>
        <div class="subtitle">Intrusion Detection & Prevention System</div>
        
        <div>
            <a href="auth/login.php" class="btn">Login</a>
            <a href="auth/register.php" class="btn">Register</a>
        </div>
        
        <div class="features">
            <strong>Security Features:</strong>
            <ul style="margin-top: 10px; margin-left: 20px;">
                <li>✅ Real-time Intrusion Detection</li>
                <li>✅ AES-256 Encryption</li>
                <li>✅ SQL Injection Prevention</li>
                <li>✅ XSS Protection</li>
                <li>✅ Automatic IP Blocking</li>
                <li>✅ Failed Login Detection</li>
            </ul>
        </div>
    </div>
</body>
</html>