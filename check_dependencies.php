<?php
// File: check_dependencies.php
// Script untuk cek dependencies dan generate VAPID keys

echo "=== CHECKING DEPENDENCIES ===\n";

// 1. Check PHP version
echo "PHP Version: " . PHP_VERSION . "\n";
if (version_compare(PHP_VERSION, '7.1.0', '<')) {
    echo "ERROR: PHP 7.1+ required for WebPush\n";
    exit(1);
}

// 2. Check required extensions
$required_extensions = ['openssl', 'gmp', 'mbstring', 'curl'];
foreach ($required_extensions as $ext) {
    if (extension_loaded($ext)) {
        echo "✓ Extension $ext: LOADED\n";
    } else {
        echo "✗ Extension $ext: MISSING\n";
    }
}

// 3. Check if composer autoload exists
if (file_exists('vendor/autoload.php')) {
    echo "✓ Composer autoload: EXISTS\n";
    require_once 'vendor/autoload.php';
} else {
    echo "✗ Composer autoload: MISSING\n";
    echo "Run: composer install\n";
    exit(1);
}

// 4. Check WebPush class
if (class_exists('Minishlink\WebPush\WebPush')) {
    echo "✓ WebPush class: AVAILABLE\n";
} else {
    echo "✗ WebPush class: NOT FOUND\n";
    echo "Run: composer require minishlink/web-push\n";
    exit(1);
}

// 5. Check VAPID class
if (class_exists('Minishlink\WebPush\VAPID')) {
    echo "✓ VAPID class: AVAILABLE\n";
} else {
    echo "✗ VAPID class: NOT FOUND\n";
    exit(1);
}

echo "\n=== GENERATING VAPID KEYS ===\n";

try {
    // Method 1: Using WebPush VAPID
    if (method_exists('Minishlink\WebPush\VAPID', 'createVapidKeys')) {
        $keys = \Minishlink\WebPush\VAPID::createVapidKeys();
        
        echo "SUCCESS: VAPID keys generated!\n";
        echo "Public Key: " . $keys['publicKey'] . "\n";
        echo "Private Key: " . $keys['privateKey'] . "\n\n";
        
        echo "=== UPDATE YOUR CONFIG ===\n";
        echo "define('VAPID_PUBLIC_KEY', '{$keys['publicKey']}');\n";
        echo "define('VAPID_PRIVATE_KEY', '{$keys['privateKey']}');\n\n";
        
    } else {
        throw new Exception("createVapidKeys method not available");
    }
    
} catch (Exception $e) {
    echo "ERROR with Method 1: " . $e->getMessage() . "\n";
    echo "Trying alternative method...\n\n";
    
    try {
        // Method 2: Manual generation using OpenSSL
        echo "=== ALTERNATIVE METHOD: OpenSSL ===\n";
        
        // Generate private key
        $private_key = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        
        if (!$private_key) {
            throw new Exception("Failed to generate private key: " . openssl_error_string());
        }
        
        // Get private key details
        $details = openssl_pkey_get_details($private_key);
        if (!$details) {
            throw new Exception("Failed to get key details: " . openssl_error_string());
        }
        
        // Extract private key (32 bytes)
        $private_key_raw = substr($details['ec']['d'], 0, 32);
        $private_key_base64 = rtrim(strtr(base64_encode($private_key_raw), '+/', '-_'), '=');
        
        // Extract public key (65 bytes, remove first byte)
        $public_key_raw = substr($details['ec']['q'], 1, 64);
        $public_key_base64 = rtrim(strtr(base64_encode($public_key_raw), '+/', '-_'), '=');
        
        echo "SUCCESS: Manual VAPID keys generated!\n";
        echo "Public Key: " . $public_key_base64 . "\n";
        echo "Private Key: " . $private_key_base64 . "\n\n";
        
        echo "=== UPDATE YOUR CONFIG ===\n";
        echo "define('VAPID_PUBLIC_KEY', '{$public_key_base64}');\n";
        echo "define('VAPID_PRIVATE_KEY', '{$private_key_base64}');\n\n";
        
    } catch (Exception $e2) {
        echo "ERROR with Method 2: " . $e2->getMessage() . "\n";
        echo "\n=== MANUAL SOLUTION ===\n";
        echo "Use online VAPID generator: https://vapidkeys.com/\n";
        echo "Or install node.js and run: npx web-push generate-vapid-keys\n";
    }
}
?>