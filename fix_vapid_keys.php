<?php
// File: fix_vapid_keys.php
// Script untuk fix VAPID keys dan reset subscriptions

echo "=== FIXING VAPID KEYS ===\n";

// Step 1: Generate new VAPID keys
echo "1. Generating new VAPID keys...\n";

// Manual VAPID key generation menggunakan OpenSSL (karena WebPush library error)
function generateVapidKeys() {
    // Generate private key
    $private_key = openssl_pkey_new([
        'curve_name' => 'prime256v1',
        'private_key_type' => OPENSSL_KEYTYPE_EC,
    ]);
    
    if (!$private_key) {
        throw new Exception("Failed to generate private key");
    }
    
    // Get key details
    $details = openssl_pkey_get_details($private_key);
    if (!$details) {
        throw new Exception("Failed to get key details");
    }
    
    // Extract private key (32 bytes)
    $private_key_raw = substr($details['ec']['d'], 0, 32);
    $private_key_base64 = rtrim(strtr(base64_encode($private_key_raw), '+/', '-_'), '=');
    
    // Extract public key (65 bytes, remove first byte which is 0x04)
    $public_key_raw = substr($details['ec']['q'], 1, 64);
    $public_key_base64 = rtrim(strtr(base64_encode($public_key_raw), '+/', '-_'), '=');
    
    return [
        'publicKey' => $public_key_base64,
        'privateKey' => $private_key_base64
    ];
}

try {
    $newKeys = generateVapidKeys();
    
    echo "   ✓ New VAPID keys generated successfully!\n";
    echo "   Public Key: " . $newKeys['publicKey'] . "\n";
    echo "   Private Key: " . $newKeys['privateKey'] . "\n\n";
    
    // Step 2: Update check_notifications.php
    echo "2. Updating check_notifications.php...\n";
    
    $checkNotifContent = file_get_contents('check_notifications.php');
    
    // Replace VAPID_PUBLIC_KEY
    $checkNotifContent = preg_replace(
        "/define\('VAPID_PUBLIC_KEY',\s*'[^']*'\);/",
        "define('VAPID_PUBLIC_KEY', '{$newKeys['publicKey']}');",
        $checkNotifContent
    );
    
    // Replace VAPID_PRIVATE_KEY
    $checkNotifContent = preg_replace(
        "/define\('VAPID_PRIVATE_KEY',\s*'[^']*'\);/",
        "define('VAPID_PRIVATE_KEY', '{$newKeys['privateKey']}');",
        $checkNotifContent
    );
    
    if (file_put_contents('check_notifications.php', $checkNotifContent)) {
        echo "   ✓ check_notifications.php updated\n";
    } else {
        echo "   ✗ Failed to update check_notifications.php\n";
    }
    
    // Step 3: Create/update JavaScript config file
    echo "\n3. Creating JavaScript config file...\n";
    
    $jsConfig = <<<JS
// File: js/push-config.js
// VAPID configuration untuk push notifications
// Generated: {date('Y-m-d H:i:s')}

const PUSH_CONFIG = {
    applicationServerKey: '{$newKeys['publicKey']}',
    vapidPublicKey: '{$newKeys['publicKey']}'
};

// Export untuk module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PUSH_CONFIG;
}

// Global variable untuk browser
window.PUSH_CONFIG = PUSH_CONFIG;

console.log('Push configuration loaded with new VAPID keys');
JS;
    
    // Create js directory if not exists
    if (!is_dir('js')) {
        mkdir('js', 0755, true);
    }
    
    if (file_put_contents('js/push-config.js', $jsConfig)) {
        echo "   ✓ js/push-config.js created\n";
    } else {
        echo "   ✗ Failed to create js/push-config.js\n";
    }
    
    // Step 4: Reset push subscriptions
    echo "\n4. Resetting push subscriptions...\n";
    
    define('DB_HOST', '151.106.119.252');
    define('DB_USER', 'cbnb9676_cbnbandung_user');
    define('DB_PASS', 'Arkan@199003');
    define('DB_NAME', 'cbnb9676_cbnbandung');
    
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    if ($conn->connect_error) {
        throw new Exception("Database connection failed: " . $conn->connect_error);
    }
    
    // Backup existing subscriptions
    $backupTable = "push_subscriptions_backup_" . date('Ymd_His');
    $backupQuery = "CREATE TABLE $backupTable AS SELECT * FROM push_subscriptions";
    
    if ($conn->query($backupQuery)) {
        echo "   ✓ Backup created: $backupTable\n";
    } else {
        echo "   ✗ Backup failed: " . $conn->error . "\n";
    }
    
    // Deactivate all existing subscriptions
    $resetQuery = "UPDATE push_subscriptions SET is_active = 0, updated_at = NOW()";
    $result = $conn->query($resetQuery);
    
    if ($result) {
        $affectedRows = $conn->affected_rows;
        echo "   ✓ Deactivated $affectedRows push subscriptions\n";
    } else {
        echo "   ✗ Failed to reset subscriptions: " . $conn->error . "\n";
    }
    
    // Add VAPID key change log
    $logQuery = "INSERT INTO system_logs (event, description, created_at) 
                 VALUES ('vapid_keys_changed', 'VAPID keys regenerated and all subscriptions reset', NOW())";
    $conn->query($logQuery); // Silent fail jika table tidak ada
    
    $conn->close();
    
    // Step 5: Create update instruction for frontend
    echo "\n5. Creating frontend update instructions...\n";
    
    $updateInstructions = <<<HTML
<!DOCTYPE html>
<html>
<head>
    <title>Push Notification Update Required</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .alert { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
        .btn:hover { background: #0056b3; }
        .code { background: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; }
    </style>
</head>
<body>
    <h1>🔔 Push Notification Update</h1>
    
    <div class="alert">
        <strong>Action Required:</strong> Push notification system has been updated with new security keys. 
        All users need to re-enable notifications.
    </div>
    
    <h2>For Users:</h2>
    <p>Click the "Enable Notifications" button again in the application to continue receiving push notifications.</p>
    
    <h2>For Developers:</h2>
    <p>Update all JavaScript files that reference the old applicationServerKey:</p>
    
    <div class="code">
        const applicationServerKey = '{$newKeys['publicKey']}';
    </div>
    
    <p>Or include the new config file:</p>
    <div class="code">
        &lt;script src="js/push-config.js"&gt;&lt;/script&gt;<br>
        // Then use: PUSH_CONFIG.applicationServerKey
    </div>
    
    <button class="btn" onclick="window.location.reload()">Refresh Page</button>
    
    <script src="js/push-config.js"></script>
    <script>
        // Auto-clear old service workers and subscriptions
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.getRegistrations().then(function(registrations) {
                for(let registration of registrations) {
                    registration.unregister();
                }
                console.log('Old service workers cleared');
            });
        }
        
        // Clear localStorage flags
        localStorage.removeItem('push_subscription_active');
        localStorage.removeItem('vapid_updated');
        
        console.log('Ready for new push subscription with updated VAPID keys');
    </script>
</body>
</html>
HTML;
    
    if (file_put_contents('push_update_notice.html', $updateInstructions)) {
        echo "   ✓ Update notice created: push_update_notice.html\n";
    }
    
    echo "\n=== SUCCESS! ===\n";
    echo "VAPID keys have been updated successfully.\n";
    echo "\nNext steps:\n";
    echo "1. Update all JavaScript files to use new public key: {$newKeys['publicKey']}\n";
    echo "2. Or include: <script src=\"js/push-config.js\"></script>\n";
    echo "3. Users will need to re-subscribe to push notifications\n";
    echo "4. Test: php check_notifications.php?key=silvia15&type=full\n";
    echo "5. View update notice: {$_SERVER['HTTP_HOST']}/push_update_notice.html\n";
    
} catch (Exception $e) {
    echo "\n❌ ERROR: " . $e->getMessage() . "\n";
    echo "\nAlternative solution:\n";
    echo "1. Use online generator: https://vapidkeys.com/\n";
    echo "2. Manually update keys in check_notifications.php\n";
    echo "3. Reset push_subscriptions table\n";
}
?>