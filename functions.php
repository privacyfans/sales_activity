<?php
// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Function to check if user is logged in
function checkLogin() {
    // Check if session user_id and token exist
    if (!isset($_SESSION['user_id']) || !isset($_SESSION['token'])) {
        header("Location: login.php");
        exit();
    }
    
    // Connect to database for additional verification
    try {
        $conn = new PDO(
            "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME,
            DB_USER,
            DB_PASS,
            array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION)
        );
        
        // Verify user is still active in database
        $stmt = $conn->prepare("SELECT username, full_name, account_status FROM users WHERE id = ? AND account_status = 'active'");
        $stmt->execute([$_SESSION['user_id']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$user) {
            // If user not found or not active, logout
            session_destroy();
            header("Location: login.php");
            exit();
        }
        
        // Check session timeout
        if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > SESSION_TIMEOUT)) {
            session_destroy();
            header("Location: login.php?message=timeout");
            exit();
        }
        
        // Update last activity time
        $_SESSION['last_activity'] = time();
        
        return $user;
        
    } catch(PDOException $e) {
        die("Error: " . $e->getMessage());
    }
}

// Function to sanitize input
function sanitizeInput($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

// Function to create database connection
function createDBConnection() {
    try {
        $conn = new PDO(
            "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME,
            DB_USER,
            DB_PASS,
            array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION)
        );
        return $conn;
    } catch(PDOException $e) {
        die("Connection failed: " . $e->getMessage());
    }
}

// Function to check password strength
function checkPasswordStrength($password) {
    // Check length
    if (strlen($password) < 8) {
        return "Password must be at least 8 characters long";
    }
    
    return true;
}

// Function to validate session token
function validateToken($token) {
    return isset($_SESSION['token']) && hash_equals($_SESSION['token'], $token);
}

// Function to log user activity
function logUserActivity($user_id, $activity) {
    try {
        $conn = createDBConnection();
        $stmt = $conn->prepare("INSERT INTO user_activity_log (user_id, activity, ip_address) VALUES (?, ?, ?)");
        $stmt->execute([$user_id, $activity, $_SERVER['REMOTE_ADDR']]);
    } catch(PDOException $e) {
        // Log error silently
        error_log("Error logging user activity: " . $e->getMessage());
    }
}
?>