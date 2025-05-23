<?php
// File: save_subscription.php
// Fixed version - Type comparison issue resolved

session_start();
header('Content-Type: application/json');

// Enable error reporting for debugging
if ($_GET['debug'] ?? false) {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
}

// Only allow POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'User not authenticated']);
    exit;
}

// Database connection
define('DB_HOST', '151.106.119.252');
define('DB_USER', 'cbnb9676_cbnbandung_user');
define('DB_PASS', 'Arkan@199003');
define('DB_NAME', 'cbnb9676_cbnbandung');

try {
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    if ($conn->connect_error) {
        throw new Exception("Connection failed: " . $conn->connect_error);
    }
    
    // Get JSON input
    $inputRaw = file_get_contents('php://input');
    $input = json_decode($inputRaw, true);
    
    // Debug logging
    if ($_GET['debug'] ?? false) {
        error_log("Save subscription input: " . $inputRaw);
        error_log("Session user_id: " . print_r($_SESSION['user_id'], true));
        error_log("Session user_id type: " . gettype($_SESSION['user_id']));
    }
    
    if (!$input) {
        throw new Exception('Invalid JSON input');
    }
    
    if (!isset($input['subscription'])) {
        throw new Exception('Missing subscription data');
    }
    
    if (!isset($input['user_id'])) {
        throw new Exception('Missing user_id');
    }
    
    $subscription = $input['subscription'];
    $user_id = (int)$input['user_id'];
    
    // FIXED: Convert both to integer for proper comparison
    $session_user_id = (int)$_SESSION['user_id'];
    
    // Debug comparison
    if ($_GET['debug'] ?? false) {
        error_log("Comparing: session_user_id($session_user_id) vs provided_user_id($user_id)");
        error_log("Session type: " . gettype($session_user_id) . ", Provided type: " . gettype($user_id));
    }
    
    // Validate user exists and matches session
    if ($user_id !== $session_user_id) {
        throw new Exception("User ID mismatch - session: $session_user_id, provided: $user_id");
    }
    
    $userStmt = $conn->prepare("SELECT id, full_name FROM users WHERE id = ? AND account_status = 'active'");
    $userStmt->bind_param("i", $user_id);
    $userStmt->execute();
    $userResult = $userStmt->get_result();
    $user = $userResult->fetch_assoc();
    $userStmt->close(); // Close statement
    
    if (!$user) {
        throw new Exception('Invalid user or inactive account');
    }
    
    // Create push_subscriptions table if not exists
    $createTableSQL = "
        CREATE TABLE IF NOT EXISTS push_subscriptions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            endpoint TEXT NOT NULL,
            p256dh_key TEXT,
            auth_key TEXT,
            user_agent TEXT,
            device_info VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE,
            last_used TIMESTAMP NULL DEFAULT NULL,
            INDEX idx_user_active (user_id, is_active),
            INDEX idx_active (is_active, updated_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ";
    
    if (!$conn->query($createTableSQL)) {
        throw new Exception('Failed to create table: ' . $conn->error);
    }
    
    // Extract subscription details
    $endpoint = $subscription['endpoint'] ?? '';
    $keys = $subscription['keys'] ?? [];
    $p256dh = $keys['p256dh'] ?? null;
    $auth = $keys['auth'] ?? null;
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $deviceInfo = $input['device_info'] ?? detectDeviceInfo($userAgent);
    
    // Validate required fields
    if (empty($endpoint)) {
        throw new Exception('Missing subscription endpoint');
    }
    
    if (empty($p256dh) || empty($auth)) {
        throw new Exception('Missing subscription keys (p256dh or auth)');
    }
    
    // Check if subscription already exists
    $checkStmt = $conn->prepare("SELECT id, is_active FROM push_subscriptions WHERE user_id = ? AND endpoint = ?");
    $checkStmt->bind_param("is", $user_id, $endpoint);
    $checkStmt->execute();
    $existingResult = $checkStmt->get_result();
    $existing = $existingResult->fetch_assoc();
    $checkStmt->close(); // Close statement
    
    if ($existing) {
        // Update existing subscription
        $updateStmt = $conn->prepare("
            UPDATE push_subscriptions 
            SET p256dh_key = ?, auth_key = ?, user_agent = ?, device_info = ?, 
                updated_at = NOW(), is_active = 1, last_used = NOW() 
            WHERE user_id = ? AND endpoint = ?
        ");
        
        // Parameters: p256dh(s), auth(s), user_agent(s), device_info(s), user_id(i), endpoint(s)
        $updateStmt->bind_param("ssssis", $p256dh, $auth, $userAgent, $deviceInfo, $user_id, $endpoint);
        
        if (!$updateStmt->execute()) {
            throw new Exception('Failed to update subscription: ' . $updateStmt->error);
        }
        $updateStmt->close(); // Close statement
        
        $message = 'Subscription updated successfully';
        $action = 'updated';
    } else {
        // Insert new subscription
        $insertStmt = $conn->prepare("
            INSERT INTO push_subscriptions 
            (user_id, endpoint, p256dh_key, auth_key, user_agent, device_info, last_used) 
            VALUES (?, ?, ?, ?, ?, ?, NOW())
        ");
        
        // Parameters: user_id(i), endpoint(s), p256dh(s), auth(s), user_agent(s), device_info(s)
        $insertStmt->bind_param("isssss", $user_id, $endpoint, $p256dh, $auth, $userAgent, $deviceInfo);
        
        if (!$insertStmt->execute()) {
            throw new Exception('Failed to insert subscription: ' . $insertStmt->error);
        }
        $insertStmt->close(); // Close statement
        
        $message = 'Subscription created successfully';
        $action = 'created';
    }
    
    // Log successful subscription
    $logEntry = "[" . date('Y-m-d H:i:s') . "] Push subscription $action for user $user_id ({$user['full_name']}): $deviceInfo\n";
    if (!is_dir('logs')) {
        mkdir('logs', 0755, true);
    }
    file_put_contents('logs/push_subscriptions.log', $logEntry, FILE_APPEND | LOCK_EX);
    
    // Get total active subscriptions for this user
    $countStmt = $conn->prepare("SELECT COUNT(*) as total FROM push_subscriptions WHERE user_id = ? AND is_active = 1");
    $countStmt->bind_param("i", $user_id);
    $countStmt->execute();
    $totalSubs = $countStmt->get_result()->fetch_assoc()['total'];
    $countStmt->close(); // Close statement
    
    echo json_encode([
        'success' => true,
        'message' => $message,
        'action' => $action,
        'device_info' => $deviceInfo,
        'user_name' => $user['full_name'],
        'total_subscriptions' => (int)$totalSubs,
        'session_user_id' => $session_user_id,
        'provided_user_id' => $user_id,
        'timestamp' => time()
    ]);
    
} catch (Exception $e) {
    error_log('Save subscription error: ' . $e->getMessage());
    
    // Log error with more details
    $errorEntry = "[" . date('Y-m-d H:i:s') . "] ERROR saving subscription: " . $e->getMessage();
    $errorEntry .= "\nSession User ID: " . ($_SESSION['user_id'] ?? 'not set') . " (type: " . gettype($_SESSION['user_id'] ?? null) . ")";
    $errorEntry .= "\nProvided User ID: " . ($input['user_id'] ?? 'not set') . " (type: " . gettype($input['user_id'] ?? null) . ")";
    $errorEntry .= "\nInput: " . (isset($inputRaw) ? substr($inputRaw, 0, 500) : 'no input');
    $errorEntry .= "\n\n";
    
    if (!is_dir('logs')) {
        mkdir('logs', 0755, true);
    }
    file_put_contents('logs/push_subscription_errors.log', $errorEntry, FILE_APPEND | LOCK_EX);
    
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage(),
        'timestamp' => time(),
        'debug_info' => [
            'session_user_id' => $_SESSION['user_id'] ?? null,
            'session_user_id_type' => gettype($_SESSION['user_id'] ?? null),
            'provided_user_id' => $input['user_id'] ?? null,
            'provided_user_id_type' => gettype($input['user_id'] ?? null),
            'comparison_result' => isset($input['user_id']) ? 
                ((int)$_SESSION['user_id'] === (int)$input['user_id'] ? 'match' : 'mismatch') : 'no_provided_id',
            'has_subscription_data' => isset($input['subscription']),
            'endpoint_length' => isset($input['subscription']['endpoint']) ? strlen($input['subscription']['endpoint']) : 0,
            'has_keys' => isset($input['subscription']['keys']),
            'p256dh_length' => isset($input['subscription']['keys']['p256dh']) ? strlen($input['subscription']['keys']['p256dh']) : 0,
            'auth_length' => isset($input['subscription']['keys']['auth']) ? strlen($input['subscription']['keys']['auth']) : 0
        ]
    ]);
    
} finally {
    if (isset($conn)) {
        $conn->close();
    }
}

/**
 * Detect device info from user agent
 */
function detectDeviceInfo($userAgent) {
    $deviceInfo = 'Unknown Device';
    
    try {
        // Detect browser
        if (strpos($userAgent, 'Chrome') !== false && strpos($userAgent, 'Edg') === false) {
            $browser = 'Chrome';
        } elseif (strpos($userAgent, 'Edg') !== false) {
            $browser = 'Edge';
        } elseif (strpos($userAgent, 'Firefox') !== false) {
            $browser = 'Firefox';
        } elseif (strpos($userAgent, 'Safari') !== false && strpos($userAgent, 'Chrome') === false) {
            $browser = 'Safari';
        } else {
            $browser = 'Other';
        }
        
        // Detect device type
        if (strpos($userAgent, 'Mobile') !== false || strpos($userAgent, 'Android') !== false) {
            $device = 'Mobile';
        } elseif (strpos($userAgent, 'Tablet') !== false || strpos($userAgent, 'iPad') !== false) {
            $device = 'Tablet';
        } else {
            $device = 'Desktop';
        }
        
        // Detect OS
        if (strpos($userAgent, 'Windows') !== false) {
            $os = 'Windows';
        } elseif (strpos($userAgent, 'Mac') !== false) {
            $os = 'macOS';
        } elseif (strpos($userAgent, 'Linux') !== false) {
            $os = 'Linux';
        } elseif (strpos($userAgent, 'Android') !== false) {
            $os = 'Android';
        } elseif (strpos($userAgent, 'iOS') !== false) {
            $os = 'iOS';
        } else {
            $os = 'Other';
        }
        
        $deviceInfo = "$browser $device ($os)";
        
    } catch (Exception $e) {
        // Fallback if detection fails
        $deviceInfo = 'Browser Device';
    }
    
    return $deviceInfo;
}
?>