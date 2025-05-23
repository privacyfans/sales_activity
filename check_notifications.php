<?php
// File: check_notifications.php
// Fixed version - MySQL Commands out of sync error

// Hanya bisa dijalankan dari command line atau dengan key yang benar
if (php_sapi_name() !== 'cli' && (!isset($_GET['key']) || $_GET['key'] !== 'silvia15')) {
    // Allow AJAX calls from authenticated users
    session_start();
    if (!isset($_SESSION['user_id'])) {
        http_response_code(403);
        die(json_encode(['success' => false, 'error' => 'Access denied']));
    }
}

// Include konfigurasi database
define('DB_HOST', '151.106.119.252');
define('DB_USER', 'cbnb9676_cbnbandung_user');
define('DB_PASS', 'Arkan@199003');
define('DB_NAME', 'cbnb9676_cbnbandung');

require_once 'notification_manager.php';

// Include Web Push library untuk push notifications
$webPushAvailable = false;
if (file_exists('vendor/autoload.php')) {
    require_once 'vendor/autoload.php';
    $webPushAvailable = class_exists('Minishlink\WebPush\WebPush');
}

// VAPID Configuration
define('VAPID_PUBLIC_KEY', 'BPHuRLM1oyf-ldW0f26TyKY08WFq3meeWW6vyvxxm9N-KPwxZBOsKM6XbhK7BKwii48yy0DV8kGo_6DH_cujRLg');
define('VAPID_PRIVATE_KEY', 'r1sqBadQB1wxkQQLxnAuILJ5K-zlAzzDGdVZzpjuUs8');
define('VAPID_SUBJECT', 'mailto: <privacyfans@gmail.com>');

try {
    // Koneksi database
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    if ($conn->connect_error) {
        throw new Exception("Connection failed: " . $conn->connect_error);
    }
    
    // Handle different request types
    $requestType = $_GET['type'] ?? 'full';
    $specificUserId = $_GET['user_id'] ?? null;
    
    if ($requestType === 'quick' && $specificUserId) {
        // Quick check untuk AJAX dari browser - hanya return data
        $quickResult = getQuickNotificationData($conn, $specificUserId);
        
        header('Content-Type: application/json');
        echo json_encode($quickResult);
        exit;
    }
    
    // Full notification check and creation
    $notificationManager = new NotificationManager($conn);
    
    $log = [];
    $log[] = "[" . date('Y-m-d H:i:s') . "] Starting notification check...";
    
    $dueTodayCount = 0;
    $overdueCount = 0;
    $pushNotificationsSent = 0;
    
    // Check untuk notifikasi jatuh tempo hari ini
    if ($requestType === 'full' || $requestType === 'due_today') {
        $dueTodayCount = $notificationManager->checkDueTodayNotifications();
        $log[] = "Due today notifications created: $dueTodayCount";
    }
    
    // Check untuk notifikasi overdue
    if ($requestType === 'full' || $requestType === 'overdue') {
        $overdueCount = $notificationManager->checkOverdueNotifications();
        $log[] = "Overdue notifications created: $overdueCount";
    }
    
    // Send Push Notifications if there are new notifications
    if (($dueTodayCount > 0 || $overdueCount > 0) && $webPushAvailable) {
        $pushResult = sendPushNotifications($conn, $dueTodayCount, $overdueCount);
        $pushNotificationsSent = $pushResult['sent'];
        $log[] = "Push notifications sent: {$pushResult['sent']}, failed: {$pushResult['failed']}";
    }
    
    // Cleanup notifikasi lama (hanya untuk full check)
    if ($requestType === 'full') {
        $cleanupResult = $notificationManager->cleanupOldNotifications();
        $log[] = "Old notifications cleaned up: " . ($cleanupResult ? "Success" : "Failed");
    }
    
    $log[] = "Notification check completed successfully";
    
    // Create logs directory if not exists
    if (!is_dir('logs')) {
        mkdir('logs', 0755, true);
    }
    
    // Log hasil
    $logEntry = implode("\n", $log) . "\n\n";
    file_put_contents('logs/notification.log', $logEntry, FILE_APPEND | LOCK_EX);
    
    // Response
    if (php_sapi_name() !== 'cli') {
        header('Content-Type: application/json');
        echo json_encode([
            'success' => true,
            'due_today' => $dueTodayCount,
            'overdue' => $overdueCount,
            'push_sent' => $pushNotificationsSent,
            'hasNewNotifications' => ($dueTodayCount + $overdueCount) > 0,
            'message' => 'Notifications checked successfully',
            'timestamp' => time()
        ]);
    } else {
        echo implode("\n", $log) . "\n";
    }
    
} catch (Exception $e) {
    $error = "[" . date('Y-m-d H:i:s') . "] ERROR: " . $e->getMessage() . "\n";
    
    // Create logs directory if not exists
    if (!is_dir('logs')) {
        mkdir('logs', 0755, true);
    }
    
    file_put_contents('logs/notification_error.log', $error, FILE_APPEND | LOCK_EX);
    
    if (php_sapi_name() !== 'cli') {
        header('Content-Type: application/json');
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage(),
            'timestamp' => time()
        ]);
    } else {
        echo "ERROR: " . $e->getMessage() . "\n";
    }
} finally {
    if (isset($conn)) {
        $conn->close();
    }
}

/**
 * Get quick notification data for AJAX requests - FIXED version
 */
function getQuickNotificationData($conn, $userId) {
    try {
        // Get user role for filtering
        $userStmt = $conn->prepare("SELECT role FROM users WHERE id = ? AND account_status = 'active'");
        if (!$userStmt) {
            throw new Exception('Failed to prepare user statement: ' . $conn->error);
        }
        
        $userStmt->bind_param("i", $userId);
        $userStmt->execute();
        $userResult = $userStmt->get_result();
        $user = $userResult->fetch_assoc();
        $userStmt->close();  // FIXED: Close statement properly
        
        if (!$user) {
            throw new Exception('User not found');
        }
        
        $today = date('Y-m-d');
        
        // Count due today - FIXED: Proper statement handling
        $dueTodaySQL = "SELECT COUNT(*) as count FROM sales_visit 
                        WHERE DATE(jatuh_tempo_pemasangan) = ? 
                        AND status IN ('Request', 'Connected')";
        
        // Count overdue - FIXED: Proper statement handling
        $overdueSQL = "SELECT COUNT(*) as count FROM sales_visit 
                       WHERE DATE(jatuh_tempo_pemasangan) < ? 
                       AND status IN ('Request')";
        
        $dueToday = 0;
        $overdue = 0;
        
        // Add role-based filtering for sales users
        if ($user['role'] === 'sales') {
            $dueTodaySQL .= " AND created_by = ?";
            $overdueSQL .= " AND created_by = ?";
            
            // Due today query
            $dueTodayStmt = $conn->prepare($dueTodaySQL);
            if (!$dueTodayStmt) {
                throw new Exception('Failed to prepare due today statement: ' . $conn->error);
            }
            $dueTodayStmt->bind_param("si", $today, $userId);
            $dueTodayStmt->execute();
            $dueTodayResult = $dueTodayStmt->get_result();
            $dueToday = $dueTodayResult->fetch_assoc()['count'];
            $dueTodayStmt->close();  // FIXED: Close statement
            
            // Overdue query
            $overdueStmt = $conn->prepare($overdueSQL);
            if (!$overdueStmt) {
                throw new Exception('Failed to prepare overdue statement: ' . $conn->error);
            }
            $overdueStmt->bind_param("si", $today, $userId);
            $overdueStmt->execute();
            $overdueResult = $overdueStmt->get_result();
            $overdue = $overdueResult->fetch_assoc()['count'];
            $overdueStmt->close();  // FIXED: Close statement
            
        } else {
            // Due today query for admin
            $dueTodayStmt = $conn->prepare($dueTodaySQL);
            if (!$dueTodayStmt) {
                throw new Exception('Failed to prepare due today statement: ' . $conn->error);
            }
            $dueTodayStmt->bind_param("s", $today);
            $dueTodayStmt->execute();
            $dueTodayResult = $dueTodayStmt->get_result();
            $dueToday = $dueTodayResult->fetch_assoc()['count'];
            $dueTodayStmt->close();  // FIXED: Close statement
            
            // Overdue query for admin
            $overdueStmt = $conn->prepare($overdueSQL);
            if (!$overdueStmt) {
                throw new Exception('Failed to prepare overdue statement: ' . $conn->error);
            }
            $overdueStmt->bind_param("s", $today);
            $overdueStmt->execute();
            $overdueResult = $overdueStmt->get_result();
            $overdue = $overdueResult->fetch_assoc()['count'];
            $overdueStmt->close();  // FIXED: Close statement
        }
        
        // Get unread notification count - FIXED: Proper statement handling
        $unreadStmt = $conn->prepare("SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0");
        if (!$unreadStmt) {
            throw new Exception('Failed to prepare unread statement: ' . $conn->error);
        }
        $unreadStmt->bind_param("i", $userId);
        $unreadStmt->execute();
        $unreadResult = $unreadStmt->get_result();
        $unreadCount = $unreadResult->fetch_assoc()['count'];
        $unreadStmt->close();  // FIXED: Close statement
        
        return [
            'success' => true,
            'due_today' => (int)$dueToday,
            'overdue' => (int)$overdue,
            'unread_notifications' => (int)$unreadCount,
            'hasNewNotifications' => ($dueToday > 0 || $overdue > 0),
            'total_urgent' => (int)($dueToday + $overdue),
            'timestamp' => time(),
            'user_role' => $user['role']
        ];
        
    } catch (Exception $e) {
        // Make sure to close any open statements in case of error
        if (isset($userStmt) && $userStmt instanceof mysqli_stmt) {
            $userStmt->close();
        }
        if (isset($dueTodayStmt) && $dueTodayStmt instanceof mysqli_stmt) {
            $dueTodayStmt->close();
        }
        if (isset($overdueStmt) && $overdueStmt instanceof mysqli_stmt) {
            $overdueStmt->close();
        }
        if (isset($unreadStmt) && $unreadStmt instanceof mysqli_stmt) {
            $unreadStmt->close();
        }
        
        return [
            'success' => false,
            'error' => $e->getMessage(),
            'timestamp' => time()
        ];
    }
}

/**
 * Send push notifications to subscribed users - FIXED version
 */
function sendPushNotifications($conn, $dueTodayCount, $overdueCount) {
    if (!class_exists('Minishlink\WebPush\WebPush')) {
        return ['sent' => 0, 'failed' => 0, 'error' => 'WebPush library not available'];
    }
    
    try {
        // Initialize WebPush
        $webPush = new \Minishlink\WebPush\WebPush([
            'VAPID' => [
                'subject' => VAPID_SUBJECT,
                'publicKey' => VAPID_PUBLIC_KEY,
                'privateKey' => VAPID_PRIVATE_KEY,
            ]
        ]);
        
        // Get active push subscriptions - FIXED: Proper statement handling
        $subscriptionSQL = "SELECT ps.*, u.full_name, u.role, u.id as user_id
                           FROM push_subscriptions ps 
                           JOIN users u ON ps.user_id = u.id 
                           WHERE ps.is_active = 1 AND u.account_status = 'active'";
        
        $subscriptionStmt = $conn->prepare($subscriptionSQL);
        if (!$subscriptionStmt) {
            throw new Exception('Failed to prepare subscription statement: ' . $conn->error);
        }
        
        $subscriptionStmt->execute();
        $subscriptionResult = $subscriptionStmt->get_result();
        $subscriptions = $subscriptionResult->fetch_all(MYSQLI_ASSOC);
        $subscriptionStmt->close();  // FIXED: Close statement
        
        if (empty($subscriptions)) {
            return ['sent' => 0, 'failed' => 0, 'error' => 'No active subscriptions'];
        }
        
        $sent = 0;
        $failed = 0;
        $today = date('Y-m-d');
        
        foreach ($subscriptions as $sub) {
            try {
                // Get user-specific due/overdue counts
                $userDueData = getUserDueData($conn, $sub['user_id'], $sub['role'], $today);
                
                // Only send if user has due/overdue visits
                if ($userDueData['due_today'] > 0 || $userDueData['overdue'] > 0) {
                    
                    // Create subscription object
                    $subscription = \Minishlink\WebPush\Subscription::create([
                        'endpoint' => $sub['endpoint'],
                        'keys' => [
                            'p256dh' => $sub['p256dh_key'],
                            'auth' => $sub['auth_key']
                        ]
                    ]);
                    
                    // Create notification payload
                    $title = 'Sales Visit Alert';
                    $body = '';
                    $urgency = 'normal';
                    
                    if ($userDueData['overdue'] > 0 && $userDueData['due_today'] > 0) {
                        $title = '🚨 Urgent: Multiple Due Visits';
                        $body = "{$userDueData['overdue']} overdue, {$userDueData['due_today']} due today";
                        $urgency = 'high';
                    } elseif ($userDueData['overdue'] > 0) {
                        $title = '⚠️ Overdue Sales Visits';
                        $body = "{$userDueData['overdue']} sales visit(s) are overdue";
                        $urgency = 'high';
                    } else {
                        $title = '📅 Due Today Reminder';
                        $body = "{$userDueData['due_today']} sales visit(s) due today";
                    }
                    
                    $payload = json_encode([
                        'title' => $title,
                        'body' => $body,
                        'icon' => '/icons/icon-192.png',
                        'badge' => '/icons/badge.png',
                        'tag' => 'sales-visit-' . $sub['user_id'] . '-' . date('Ymd'),
                        'requireInteraction' => $urgency === 'high',
                        'data' => [
                            'url' => '/sales_visit.php?due_filter=' . ($userDueData['overdue'] > 0 ? 'overdue' : 'due_today'),
                            'user_id' => $sub['user_id'],
                            'urgency' => $urgency,
                            'timestamp' => time()
                        ],
                        'actions' => [
                            [
                                'action' => 'view',
                                'title' => 'View Details',
                                'icon' => '/icons/view.png'
                            ],
                            [
                                'action' => 'dismiss',
                                'title' => 'Dismiss',
                                'icon' => '/icons/close.png'
                            ]
                        ],
                        'vibrate' => $urgency === 'high' ? [200, 100, 200, 100, 200] : [200, 100, 200]
                    ]);
                    
                    // Send notification
                    $result = $webPush->sendOneNotification($subscription, $payload);
                    
                    if ($result->isSuccess()) {
                        $sent++;
                        
                        // Log successful send
                        $logEntry = "[" . date('Y-m-d H:i:s') . "] Push notification sent to user {$sub['user_id']} ({$sub['full_name']})\n";
                        if (!is_dir('logs')) mkdir('logs', 0755, true);
                        file_put_contents('logs/push_notifications.log', $logEntry, FILE_APPEND | LOCK_EX);
                        
                    } else {
                        $failed++;
                        
                        // Log failure
                        $errorMsg = "[" . date('Y-m-d H:i:s') . "] Push notification failed for user {$sub['user_id']}: " . $result->getReason() . "\n";
                        if (!is_dir('logs')) mkdir('logs', 0755, true);
                        file_put_contents('logs/push_notifications_error.log', $errorMsg, FILE_APPEND | LOCK_EX);
                        
                        // Disable subscription if permanently failed
                        if ($result->isSubscriptionExpired()) {
                            $updateStmt = $conn->prepare("UPDATE push_subscriptions SET is_active = 0, updated_at = NOW() WHERE id = ?");
                            if ($updateStmt) {
                                $updateStmt->bind_param("i", $sub['id']);
                                $updateStmt->execute();
                                $updateStmt->close();  // FIXED: Close statement
                            }
                        }
                    }
                }
                
            } catch (Exception $e) {
                $failed++;
                $errorMsg = "[" . date('Y-m-d H:i:s') . "] Error processing push notification for user {$sub['user_id']}: " . $e->getMessage() . "\n";
                if (!is_dir('logs')) mkdir('logs', 0755, true);
                file_put_contents('logs/push_notifications_error.log', $errorMsg, FILE_APPEND | LOCK_EX);
            }
        }
        
        return [
            'sent' => $sent,
            'failed' => $failed,
            'total_subscriptions' => count($subscriptions)
        ];
        
    } catch (Exception $e) {
        $errorMsg = "[" . date('Y-m-d H:i:s') . "] Push notification system error: " . $e->getMessage() . "\n";
        if (!is_dir('logs')) mkdir('logs', 0755, true);
        file_put_contents('logs/push_notifications_error.log', $errorMsg, FILE_APPEND | LOCK_EX);
        
        return [
            'sent' => 0,
            'failed' => 0,
            'error' => $e->getMessage()
        ];
    }
}

/**
 * Get user-specific due data - FIXED version
 */
function getUserDueData($conn, $userId, $userRole, $today) {
    try {
        // Separate queries to avoid complexity
        $dueToday = 0;
        $overdue = 0;
        
        // Query for due today
        $dueTodaySQL = "SELECT COUNT(*) as count FROM sales_visit 
                        WHERE DATE(jatuh_tempo_pemasangan) = ? 
                        AND status IN ('Request', 'Connected')";
        
        if ($userRole === 'sales') {
            $dueTodaySQL .= " AND created_by = ?";
            $dueTodayStmt = $conn->prepare($dueTodaySQL);
            if ($dueTodayStmt) {
                $dueTodayStmt->bind_param("si", $today, $userId);
                $dueTodayStmt->execute();
                $dueTodayResult = $dueTodayStmt->get_result();
                $dueToday = $dueTodayResult->fetch_assoc()['count'];
                $dueTodayStmt->close();
            }
        } else {
            $dueTodayStmt = $conn->prepare($dueTodaySQL);
            if ($dueTodayStmt) {
                $dueTodayStmt->bind_param("s", $today);
                $dueTodayStmt->execute();
                $dueTodayResult = $dueTodayStmt->get_result();
                $dueToday = $dueTodayResult->fetch_assoc()['count'];
                $dueTodayStmt->close();
            }
        }
        
        // Query for overdue
        $overdueSQL = "SELECT COUNT(*) as count FROM sales_visit 
                       WHERE DATE(jatuh_tempo_pemasangan) < ? 
                       AND status IN ('Request')";
        
        if ($userRole === 'sales') {
            $overdueSQL .= " AND created_by = ?";
            $overdueStmt = $conn->prepare($overdueSQL);
            if ($overdueStmt) {
                $overdueStmt->bind_param("si", $today, $userId);
                $overdueStmt->execute();
                $overdueResult = $overdueStmt->get_result();
                $overdue = $overdueResult->fetch_assoc()['count'];
                $overdueStmt->close();
            }
        } else {
            $overdueStmt = $conn->prepare($overdueSQL);
            if ($overdueStmt) {
                $overdueStmt->bind_param("s", $today);
                $overdueStmt->execute();
                $overdueResult = $overdueStmt->get_result();
                $overdue = $overdueResult->fetch_assoc()['count'];
                $overdueStmt->close();
            }
        }
        
        return [
            'due_today' => (int)$dueToday,
            'overdue' => (int)$overdue
        ];
        
    } catch (Exception $e) {
        // Close any open statements
        if (isset($dueTodayStmt) && $dueTodayStmt instanceof mysqli_stmt) {
            $dueTodayStmt->close();
        }
        if (isset($overdueStmt) && $overdueStmt instanceof mysqli_stmt) {
            $overdueStmt->close();
        }
        
        return [
            'due_today' => 0,
            'overdue' => 0
        ];
    }
}
?>