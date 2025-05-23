<?php
// File: generate_vapid.php
// Script untuk generate VAPID keys baru

require_once 'vendor/autoload.php';

use Minishlink\WebPush\VAPID;

try {
    // Generate new VAPID keys
    $keys = VAPID::createVapidKeys();
    
    echo "=== NEW VAPID KEYS ===\n";
    echo "Public Key: " . $keys['publicKey'] . "\n";
    echo "Private Key: " . $keys['privateKey'] . "\n\n";
    
    echo "=== UPDATE YOUR CONFIG ===\n";
    echo "define('VAPID_PUBLIC_KEY', '{$keys['publicKey']}');\n";
    echo "define('VAPID_PRIVATE_KEY', '{$keys['privateKey']}');\n\n";
    
    echo "=== UPDATE YOUR JAVASCRIPT ===\n";
    echo "const applicationServerKey = '{$keys['publicKey']}';\n\n";
    
    echo "IMPORTANT: Setelah update keys, semua existing subscriptions harus di-reset!\n";
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
?>