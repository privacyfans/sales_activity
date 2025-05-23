<?php
// File: send_push_notification.php
// Kirim push notification (untuk testing atau cron job)

session_start();

// Database connection
define('DB_HOST', '151.106.119.252');
define('DB_USER', 'cbnb9676_cbnbandung_user');
define('DB_PASS', 'Arkan@199003');
define('DB_NAME', 'cbnb9676_cbnbandung');

// VAPID Keys - Generate from https://web-push-codelab.glitch.me/
define('VAPID_PUBLIC_KEY', 'BPHuRLM1oyf-ldW0f26TyKY08WFq3meeWW6vyvxxm9N-KPwxZBOsKM6XbhK7BKwii48yy0DV8kGo_6DH_cujRLg');
define('VAPID_PRIVATE_KEY', 'r1sqBadQB1wxkQQLxnAuILJ5K-zlAzzDGdVZzpjuUs8');
define('VAPID_SUBJECT', 'mailto:privacyfans@gmail.com');

// Install Web Push library: composer require minishlink/web-push
require_once 'vendor/autoload.php';

use Minishlink\WebPush\WebPush;
use Minishlink\WebPush\Subscription;

try {
    $conn = new PDO(
        "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME,
        DB_USER,
        DB_PASS,
        array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION)
    );
    
    // Initialize WebPush
    $webPush = new WebPush([
        'VAPID' => [
            'subject' => VAPID_SUBJECT,
            'publicKey' => VAPID_PUBLIC_KEY,
            'privateKey' => VAPID_PRIVATE_KEY,
        ]
    ]);
    
    // Get all active subscriptions
    $stmt = $conn->prepare("
        SELECT ps.*, u.full_name, u.role 
        FROM push_subscriptions ps 
        JOIN users u ON ps.user_id = u.id 
        WHERE ps.is_active = 1 AND u.account_status = 'active'
    ");
    $stmt->execute();
    $subscriptions = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    if (empty($subscriptions)) {
        echo json_encode(['success' => false, 'message' => 'No active subscriptions found']);
        exit;
    }
    
    $today = date('Y-m-d');
    $successCount = 0;
    $failCount = 0;
    
    foreach ($subscriptions as $sub) {
        try {
            // Check due visits for this user
            $dueSQL = "SELECT COUNT(*) as due_today, 
                       (SELECT COUNT(*) FROM sales_visit WHERE DATE(jatuh_tempo_pemasangan) < ? AND status IN ('Request') " .
                       ($sub['role'] === 'sales' ? " AND created_by = ?" : "") . ") as overdue
                       FROM sales_visit 
                       WHERE DATE(jatuh_tempo_pemasangan) = ? AND status IN ('Request', 'Connected')" .
                       ($sub['role'] === 'sales' ? " AND created_by = ?" : "");
            
            $dueStmt = $conn->prepare($dueSQL);
            
            if ($sub['role'] === 'sales') {
                $dueStmt->execute([$today, $sub['user_id'], $today, $sub['user_id']]);
            } else {
                $dueStmt->execute([$today, $today]);
            }
            
            $dueData = $dueStmt->fetch(PDO::FETCH_ASSOC);
            
            // Only send if there are due/overdue visits
            if ($dueData['due_today'] > 0 || $dueData['overdue'] > 0) {
                
                // Create subscription object
                $subscription = Subscription::create([
                    'endpoint' => $sub['endpoint'],
                    'keys' => [
                        'p256dh' => $sub['p256dh_key'],
                        'auth' => $sub['auth_key']
                    ]
                ]);
                
                // Create notification payload
                $payload = json_encode([
                    'title' => 'Sales Visit Alert - ' . $sub['full_name'],
                    'body' => ($dueData['overdue'] > 0 ? 
                              "⚠️ {$dueData['overdue']} overdue, {$dueData['due_today']} due today" :
                              "📅 {$dueData['due_today']} sales visit due today"),
                    'icon' => '/icons/icon-192.png',
                    'badge' => '/icons/badge.png',
                    'tag' => 'sales-visit-' . $sub['user_id'],
                    'data' => [
                        'url' => '/sales_visit.php?due_filter=' . ($dueData['overdue'] > 0 ? 'overdue' : 'due_today'),
                        'user_id' => $sub['user_id']
                    ],
                    'actions' => [
                        ['action' => 'view', 'title' => 'Lihat Detail'],
                        ['action' => 'dismiss', 'title' => 'Tutup']
                    ]
                ]);
                
                // Send notification
                $result = $webPush->sendOneNotification($subscription, $payload);
                
                if ($result->isSuccess()) {
                    $successCount++;
                } else {
                    $failCount++;
                    error_log('Push notification failed for user ' . $sub['user_id'] . ': ' . $result->getReason());
                    
                    // Disable subscription if permanently failed
                    if ($result->isSubscriptionExpired()) {
                        $updateStmt = $conn->prepare("UPDATE push_subscriptions SET is_active = 0 WHERE id = ?");
                        $updateStmt->execute([$sub['id']]);
                    }
                }
            }
            
        } catch (Exception $e) {
            $failCount++;
            error_log('Error processing subscription for user ' . $sub['user_id'] . ': ' . $e->getMessage());
        }
    }
    
    echo json_encode([
        'success' => true,
        'sent' => $successCount,
        'failed' => $failCount,
        'total_subscriptions' => count($subscriptions)
    ]);
    
} catch (Exception $e) {
    error_log('Send push notification error: ' . $e->getMessage());
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
?>