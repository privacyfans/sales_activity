<?php
// File: notification_manager.php
// Class untuk mengelola notifikasi - FIXED VERSION

class NotificationManager {
    private $conn;
    private $webPushAvailable = false;
    
    public function __construct($database_connection) {
        $this->conn = $database_connection;
        
        // Check if WebPush is available
        if (file_exists('vendor/autoload.php')) {
            require_once 'vendor/autoload.php';
            $this->webPushAvailable = class_exists('Minishlink\WebPush\WebPush');
        }
    }
    
    // Check untuk sales visit yang jatuh tempo hari ini
    public function checkDueTodayNotifications() {
        $today = date('Y-m-d');
        
        // Query untuk mencari sales visit yang jatuh tempo hari ini
        $sql = "SELECT sv.*, u.id as user_id, u.full_name, u.role
                FROM sales_visit sv
                JOIN users u ON sv.created_by = u.id
                WHERE DATE(sv.jatuh_tempo_pemasangan) = ?
                AND sv.status IN ('Request', 'Connected')
                AND u.account_status = 'active'";
        
        $stmt = $this->conn->prepare($sql);
        if (!$stmt) {
            throw new Exception('Failed to prepare due today statement: ' . $this->conn->error);
        }
        
        $stmt->bind_param("s", $today);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $notifications_created = 0;
        
        while ($row = $result->fetch_assoc()) {
            // Cek apakah notifikasi untuk sales visit ini sudah dibuat hari ini
            if (!$this->isNotificationSent($row['id'], 'due_today', $today)) {
                $this->createNotification($row);
                $this->logNotification($row['id'], 'due_today', $today);
                $notifications_created++;
            }
        }
        
        $stmt->close();
        return $notifications_created;
    }
    
    // Check untuk sales visit yang overdue
    public function checkOverdueNotifications() {
        $today = date('Y-m-d');
        
        $sql = "SELECT sv.*, u.id as user_id, u.full_name, u.role
                FROM sales_visit sv
                JOIN users u ON sv.created_by = u.id
                WHERE DATE(sv.jatuh_tempo_pemasangan) < ?
                AND sv.status IN ('Request')
                AND u.account_status = 'active'";
        
        $stmt = $this->conn->prepare($sql);
        if (!$stmt) {
            throw new Exception('Failed to prepare overdue statement: ' . $this->conn->error);
        }
        
        $stmt->bind_param("s", $today);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $notifications_created = 0;
        
        while ($row = $result->fetch_assoc()) {
            if (!$this->isNotificationSent($row['id'], 'overdue', $today)) {
                $this->createOverdueNotification($row);
                $this->logNotification($row['id'], 'overdue', $today);
                $notifications_created++;
            }
        }
        
        $stmt->close();
        return $notifications_created;
    }
    
    // Buat notifikasi untuk jatuh tempo hari ini
    private function createNotification($salesVisit) {
        $title = "Jatuh Tempo Pemasangan Hari Ini";
        $message = "Sales visit untuk {$salesVisit['nama']} (ID: {$salesVisit['id_pelanggan']}) jatuh tempo hari ini. Status: {$salesVisit['status']}";
        
        $sql = "INSERT INTO notifications (user_id, sales_visit_id, type, title, message) VALUES (?, ?, 'due_today', ?, ?)";
        $stmt = $this->conn->prepare($sql);
        if (!$stmt) {
            throw new Exception('Failed to prepare notification insert: ' . $this->conn->error);
        }
        
        $stmt->bind_param("iiss", $salesVisit['user_id'], $salesVisit['id'], $title, $message);
        $stmt->execute();
        $stmt->close();
        
        // NOTE: Push notifications akan dihandle oleh check_notifications.php
        // Tidak perlu dipanggil di sini untuk menghindari duplikasi
        
        // Kirim ke admin juga
        $this->notifyAdmins($salesVisit, $title, $message);
    }
    
    // Buat notifikasi untuk overdue
    private function createOverdueNotification($salesVisit) {
        $daysOverdue = (strtotime(date('Y-m-d')) - strtotime($salesVisit['jatuh_tempo_pemasangan'])) / 86400;
        $title = "Pemasangan Terlambat";
        $message = "Sales visit untuk {$salesVisit['nama']} (ID: {$salesVisit['id_pelanggan']}) sudah terlambat {$daysOverdue} hari. Segera follow up!";
        
        $sql = "INSERT INTO notifications (user_id, sales_visit_id, type, title, message) VALUES (?, ?, 'overdue', ?, ?)";
        $stmt = $this->conn->prepare($sql);
        if (!$stmt) {
            throw new Exception('Failed to prepare overdue notification insert: ' . $this->conn->error);
        }
        
        $stmt->bind_param("iiss", $salesVisit['user_id'], $salesVisit['id'], $title, $message);
        $stmt->execute();
        $stmt->close();
        
        // NOTE: Push notifications akan dihandle oleh check_notifications.php
        $this->notifyAdmins($salesVisit, $title, $message);
    }
    
    // Notify semua admin
    private function notifyAdmins($salesVisit, $title, $message) {
        $sql = "SELECT id FROM users WHERE role = 'admin' AND account_status = 'active'";
        $stmt = $this->conn->prepare($sql);
        if (!$stmt) {
            return; // Silent fail untuk admin notifications
        }
        
        $stmt->execute();
        $result = $stmt->get_result();
        
        while ($admin = $result->fetch_assoc()) {
            if ($admin['id'] != $salesVisit['user_id']) { // Jangan duplikasi jika sales adalah admin
                $adminMessage = "[Admin Alert] " . $message . " (Sales: {$salesVisit['full_name']})";
                
                $insertSql = "INSERT INTO notifications (user_id, sales_visit_id, type, title, message) VALUES (?, ?, 'admin_alert', ?, ?)";
                $insertStmt = $this->conn->prepare($insertSql);
                if ($insertStmt) {
                    $insertStmt->bind_param("iiss", $admin['id'], $salesVisit['id'], $title, $adminMessage);
                    $insertStmt->execute();
                    $insertStmt->close();
                }
            }
        }
        
        $stmt->close();
    }
    
    // REMOVED: sendPushNotification dan sendWebPush methods
    // Push notifications sekarang dihandle oleh check_notifications.php
    
    // Cek apakah notifikasi sudah dikirim
    private function isNotificationSent($salesVisitId, $type, $date) {
        $sql = "SELECT id FROM notification_logs WHERE sales_visit_id = ? AND notification_type = ? AND sent_date = ?";
        $stmt = $this->conn->prepare($sql);
        if (!$stmt) {
            return false; // Jika gagal prepare, anggap belum dikirim
        }
        
        $stmt->bind_param("iss", $salesVisitId, $type, $date);
        $stmt->execute();
        $result = $stmt->get_result();
        $exists = $result->num_rows > 0;
        $stmt->close();
        
        return $exists;
    }
    
    // Log notifikasi yang sudah dikirim
    private function logNotification($salesVisitId, $type, $date) {
        // Create table if not exists
        $createTableSQL = "CREATE TABLE IF NOT EXISTS notification_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            sales_visit_id INT NOT NULL,
            notification_type VARCHAR(50) NOT NULL,
            sent_date DATE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_sales_visit_type_date (sales_visit_id, notification_type, sent_date)
        )";
        $this->conn->query($createTableSQL);
        
        $sql = "INSERT INTO notification_logs (sales_visit_id, notification_type, sent_date) VALUES (?, ?, ?)";
        $stmt = $this->conn->prepare($sql);
        if ($stmt) {
            $stmt->bind_param("iss", $salesVisitId, $type, $date);
            $stmt->execute();
            $stmt->close();
        }
    }
    
    // Get notifikasi untuk user
    public function getUserNotifications($userId, $limit = 10, $unreadOnly = false) {
        $sql = "SELECT n.*, sv.nama as customer_name, sv.id_pelanggan
                FROM notifications n
                LEFT JOIN sales_visit sv ON n.sales_visit_id = sv.id
                WHERE n.user_id = ?";
        
        if ($unreadOnly) {
            $sql .= " AND n.is_read = 0";
        }
        
        $sql .= " ORDER BY n.created_at DESC LIMIT ?";
        
        $stmt = $this->conn->prepare($sql);
        if (!$stmt) {
            return [];
        }
        
        $stmt->bind_param("ii", $userId, $limit);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
        
        return $result;
    }
    
    // Mark notifikasi sebagai dibaca
    public function markAsRead($notificationId, $userId) {
        $sql = "UPDATE notifications SET is_read = 1, read_at = NOW() WHERE id = ? AND user_id = ?";
        $stmt = $this->conn->prepare($sql);
        if (!$stmt) {
            return false;
        }
        
        $stmt->bind_param("ii", $notificationId, $userId);
        $result = $stmt->execute();
        $stmt->close();
        
        return $result;
    }
    
    // Get jumlah notifikasi yang belum dibaca
    public function getUnreadCount($userId) {
        $sql = "SELECT COUNT(*) as unread_count FROM notifications WHERE user_id = ? AND is_read = 0";
        $stmt = $this->conn->prepare($sql);
        if (!$stmt) {
            return 0;
        }
        
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stmt->close();
        
        return $row['unread_count'];
    }
    
    // Bersihkan notifikasi lama (lebih dari 30 hari)
    public function cleanupOldNotifications() {
        $sql = "DELETE FROM notifications WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)";
        $stmt = $this->conn->prepare($sql);
        if (!$stmt) {
            return false;
        }
        
        $result = $stmt->execute();
        $stmt->close();
        
        // Cleanup notification logs juga
        $logSql = "DELETE FROM notification_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)";
        $logStmt = $this->conn->prepare($logSql);
        if ($logStmt) {
            $logStmt->execute();
            $logStmt->close();
        }
        
        return $result;
    }
    
    // Get statistics untuk dashboard
    public function getNotificationStats($userId = null, $userRole = null) {
        $today = date('Y-m-d');
        $stats = [];
        
        // Base query conditions
        $userCondition = "";
        $params = [];
        $paramTypes = "";
        
        if ($userId && $userRole === 'sales') {
            $userCondition = " AND sv.created_by = ?";
            $params[] = $userId;
            $paramTypes .= "i";
        }
        
        // Due today count
        $dueTodaySQL = "SELECT COUNT(*) as count FROM sales_visit sv 
                        WHERE DATE(sv.jatuh_tempo_pemasangan) = ? 
                        AND sv.status IN ('Request', 'Connected') $userCondition";
        
        $stmt = $this->conn->prepare($dueTodaySQL);
        if ($stmt) {
            $allParams = array_merge([$today], $params);
            $allTypes = "s" . $paramTypes;
            $stmt->bind_param($allTypes, ...$allParams);
            $stmt->execute();
            $result = $stmt->get_result();
            $stats['due_today'] = $result->fetch_assoc()['count'];
            $stmt->close();
        } else {
            $stats['due_today'] = 0;
        }
        
        // Overdue count
        $overdueSQL = "SELECT COUNT(*) as count FROM sales_visit sv 
                       WHERE DATE(sv.jatuh_tempo_pemasangan) < ? 
                       AND sv.status IN ('Request') $userCondition";
        
        $stmt = $this->conn->prepare($overdueSQL);
        if ($stmt) {
            $allParams = array_merge([$today], $params);
            $allTypes = "s" . $paramTypes;
            $stmt->bind_param($allTypes, ...$allParams);
            $stmt->execute();
            $result = $stmt->get_result();
            $stats['overdue'] = $result->fetch_assoc()['count'];
            $stmt->close();
        } else {
            $stats['overdue'] = 0;
        }
        
        // Unread notifications count (jika user specific)
        if ($userId) {
            $stats['unread_notifications'] = $this->getUnreadCount($userId);
        }
        
        return $stats;
    }
}
?>