<?php
// File: vapid_audit.php
// Script untuk audit dan sinkronisasi VAPID keys

echo "=== VAPID KEYS AUDIT ===\n";

// 1. Check VAPID keys di check_notifications.php
echo "1. VAPID Keys in check_notifications.php:\n";
echo "   Public:  " . (defined('VAPID_PUBLIC_KEY') ? VAPID_PUBLIC_KEY : 'NOT DEFINED') . "\n";
echo "   Private: " . (defined('VAPID_PRIVATE_KEY') ? VAPID_PRIVATE_KEY : 'NOT DEFINED') . "\n\n";

// 2. Check VAPID keys di notification_manager.php (hardcoded)
echo "2. Checking notification_manager.php for hardcoded keys...\n";
$notifManagerContent = file_get_contents('notification_manager.php');
if (preg_match("/publicKey['\"]?\s*=>\s*['\"]([^'\"]+)['\"]?/", $notifManagerContent, $matches)) {
    echo "   Found hardcoded public key: " . $matches[1] . "\n";
} else {
    echo "   No hardcoded public key found\n";
}

if (preg_match("/privateKey['\"]?\s*=>\s*['\"]([^'\"]+)['\"]?/", $notifManagerContent, $matches)) {
    echo "   Found hardcoded private key: " . $matches[1] . "\n";
} else {
    echo "   No hardcoded private key found\n";
}

echo "\n3. Checking JavaScript files for applicationServerKey...\n";

// 3. Scan untuk applicationServerKey di file JavaScript
$jsFiles = glob('*.js');
$jsFiles = array_merge($jsFiles, glob('js/*.js'), glob('assets/js/*.js'));

foreach ($jsFiles as $file) {
    if (file_exists($file)) {
        $content = file_get_contents($file);
        if (preg_match("/applicationServerKey\s*=\s*['\"]([^'\"]+)['\"]?/", $content, $matches)) {
            echo "   Found in $file: " . $matches[1] . "\n";
        }
    }
}

// 4. Check database untuk existing subscriptions
echo "\n4. Checking database subscriptions...\n";
try {
    define('DB_HOST', '151.106.119.252');
    define('DB_USER', 'cbnb9676_cbnbandung_user');
    define('DB_PASS', 'Arkan@199003');
    define('DB_NAME', 'cbnb9676_cbnbandung');
    
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    if ($conn->connect_error) {
        throw new Exception("Connection failed: " . $conn->connect_error);
    }
    
    $result = $conn->query("SELECT COUNT(*) as total, 
                                   SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active 
                            FROM push_subscriptions");
    
    if ($result) {
        $row = $result->fetch_assoc();
        echo "   Total subscriptions: " . $row['total'] . "\n";
        echo "   Active subscriptions: " . $row['active'] . "\n";
        
        // Sample subscription untuk debugging
        $sampleResult = $conn->query("SELECT user_id, endpoint, created_at, is_active 
                                     FROM push_subscriptions 
                                     ORDER BY created_at DESC LIMIT 3");
        
        echo "\n   Recent subscriptions:\n";
        while ($sub = $sampleResult->fetch_assoc()) {
            $endpointPart = substr($sub['endpoint'], -50);
            echo "   - User {$sub['user_id']}: ...{$endpointPart} (Active: {$sub['is_active']}) [{$sub['created_at']}]\n";
        }
    }
    
    $conn->close();
    
} catch (Exception $e) {
    echo "   Database error: " . $e->getMessage() . "\n";
}

echo "\n=== RECOMMENDATIONS ===\n";
echo "1. Generate new VAPID keys\n";
echo "2. Update all config files with same keys\n";
echo "3. Reset all push subscriptions\n";
echo "4. Force users to re-subscribe\n";
echo "\nRun: php fix_vapid_keys.php\n";
?>