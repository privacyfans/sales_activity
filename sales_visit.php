<?php
// Start session
session_start();
define('DB_HOST', '151.106.119.252');
define('DB_USER', 'cbnb9676_cbnbandung_user');
define('DB_PASS', 'Arkan@199003');
define('DB_NAME', 'cbnb9676_cbnbandung');

require_once 'notification_manager.php';

// Fungsi untuk mengecek apakah user sudah login dan memiliki akses
function checkSalesAccess() {
    if (!isset($_SESSION['user_id']) || !isset($_SESSION['token'])) {
        header("Location: login.php");
        exit();
    }
    
    try {
        $conn = new PDO(
            "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME,
            DB_USER,
            DB_PASS,
            array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION)
        );
        $stmt = $conn->prepare("SELECT username, full_name, account_status, role FROM users WHERE id = ? AND account_status = 'active'");
        $stmt->execute([$_SESSION['user_id']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$user) {
            session_destroy();
            header("Location: login.php");
            exit();
        }
        
        // Check if user has access to sales visit (admin or sales role)
        if (!in_array($user['role'], ['admin', 'sales'])) {
            header("Location: index.php?error=access_denied");
            exit();
        }
        
        return $user;
        
    } catch(PDOException $e) {
        die("Error: " . $e->getMessage());
    }
}

$user = checkSalesAccess();
$_SESSION['last_activity'] = time();

if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > 1800)) {
    session_destroy();
    header("Location: login.php?message=timeout");
    exit();
}

// Database connection
$servername = "151.106.119.252";
$username = "cbnb9676_cbnbandung_user";
$password = "Arkan@199003";
$dbname = "cbnb9676_cbnbandung";

$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Initialize notification manager
$notificationManager = new NotificationManager($conn);

// Handle notification actions
if (isset($_POST['action']) && $_POST['action'] == 'mark_notification_read') {
    $notificationId = $_POST['notification_id'];
    $notificationManager->markAsRead($notificationId, $_SESSION['user_id']);
    echo json_encode(['success' => true]);
    exit();
}

// Handle mark all notifications as read
if (isset($_POST['action']) && $_POST['action'] == 'mark_all_notifications_read') {
    header('Content-Type: application/json');
    try {
        $sql = "UPDATE notifications SET is_read = 1, read_at = NOW() WHERE user_id = ? AND is_read = 0";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $_SESSION['user_id']);
        $success = $stmt->execute();
        
        if ($success) {
            $affectedRows = $stmt->affected_rows;
            echo json_encode([
                'success' => true, 
                'marked_count' => $affectedRows,
                'message' => "$affectedRows notifications marked as read"
            ]);
        }
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
    exit();
}

// Get notifications for current user
$notifications = $notificationManager->getUserNotifications($_SESSION['user_id'], 5);
$unreadCount = $notificationManager->getUnreadCount($_SESSION['user_id']);

// Handle form submissions
$message = '';
$messageType = '';

// Check for redirect message
if (isset($_GET['message'])) {
    $message = $_GET['message'];
    $messageType = isset($_GET['type']) ? $_GET['type'] : 'info';
}


// Create/Update
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $action = $_POST['action'];
    
    
    if ($action == 'create' || $action == 'update') {
        $id_pelanggan = $_POST['id_pelanggan'];
        $nama = $_POST['nama'];
        $alamat = $_POST['alamat'];
        $hid = $_POST['hid'];
        $no_hp = $_POST['no_hp'];
        $email = $_POST['email'];
        $paket = $_POST['paket'];
        $titik_koordinat = $_POST['titik_koordinat'];
        $tanggal_pemasangan = $_POST['tanggal_pemasangan'] ?: null;
        $jatuh_tempo_pemasangan = $_POST['jatuh_tempo_pemasangan'] ?: null;
        $status = $_POST['status'];
        
        if ($action == 'create') {
            $sql = "INSERT INTO sales_visit (id_pelanggan, nama, alamat, hid, no_hp, email, paket, titik_koordinat, tanggal_pemasangan, jatuh_tempo_pemasangan, status, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("sssssssssssi", $id_pelanggan, $nama, $alamat, $hid, $no_hp, $email, $paket, $titik_koordinat, $tanggal_pemasangan, $jatuh_tempo_pemasangan, $status, $_SESSION['user_id']);
            
            if ($stmt->execute()) {
                $message = "Data berhasil ditambahkan!";
                $messageType = "success";
            } else {
                $message = "Error: " . $conn->error;
                $messageType = "danger";
            }
        } else {
            $id = $_POST['id'];
            
            // Check if user has permission to edit this record
            $permissionSql = "SELECT created_by FROM sales_visit WHERE id = ?";
            $permissionStmt = $conn->prepare($permissionSql);
            $permissionStmt->bind_param("i", $id);
            $permissionStmt->execute();
            $permissionResult = $permissionStmt->get_result();
            
            if ($permissionResult->num_rows > 0) {
                $permissionData = $permissionResult->fetch_assoc();
                
                // Sales users can only edit their own records, admin can edit all
                if ($user['role'] === 'sales' && $permissionData['created_by'] != $_SESSION['user_id']) {
                    $message = "Anda tidak memiliki izin untuk mengedit data ini!";
                    $messageType = "danger";
                } else {
                    $sql = "UPDATE sales_visit SET id_pelanggan=?, nama=?, alamat=?, hid=?, no_hp=?, email=?, paket=?, titik_koordinat=?, tanggal_pemasangan=?, jatuh_tempo_pemasangan=?, status=?, updated_by=? WHERE id=?";
                    $stmt = $conn->prepare($sql);
                    $stmt->bind_param("sssssssssssii", $id_pelanggan, $nama, $alamat, $hid, $no_hp, $email, $paket, $titik_koordinat, $tanggal_pemasangan, $jatuh_tempo_pemasangan, $status, $_SESSION['user_id'], $id);
                    
                    if ($stmt->execute()) {
                        $message = "Data berhasil diupdate!";
                        $messageType = "success";
                    } else {
                        $message = "Error: " . $conn->error;
                        $messageType = "danger";
                    }
                }
            } else {
                $message = "Data tidak ditemukan!";
                $messageType = "danger";
            }
        }
    }

    
    
    // Delete
    if ($action == 'delete') {
        $id = $_POST['id'];
        
        // Check if user has permission to delete this record
        $permissionSql = "SELECT created_by FROM sales_visit WHERE id = ?";
        $permissionStmt = $conn->prepare($permissionSql);
        $permissionStmt->bind_param("i", $id);
        $permissionStmt->execute();
        $permissionResult = $permissionStmt->get_result();
        
        if ($permissionResult->num_rows > 0) {
            $permissionData = $permissionResult->fetch_assoc();
            
            // Sales users can only delete their own records, admin can delete all
            if ($user['role'] === 'sales' && $permissionData['created_by'] != $_SESSION['user_id']) {
                $message = "Anda tidak memiliki izin untuk menghapus data ini!";
                $messageType = "danger";
            } else {
                $sql = "DELETE FROM sales_visit WHERE id=?";
                $stmt = $conn->prepare($sql);
                $stmt->bind_param("i", $id);
                
                if ($stmt->execute()) {
                    $message = "Data berhasil dihapus!";
                    $messageType = "success";
                    
                    // Redirect back to the same page with filters preserved
                    $redirectPage = isset($_POST['redirect_page']) ? $_POST['redirect_page'] : 1;
                    $redirectSearch = isset($_POST['redirect_search']) ? $_POST['redirect_search'] : '';
                    $redirectStatus = isset($_POST['redirect_status']) ? $_POST['redirect_status'] : '';
                    
                    $redirectUrl = "sales_visit.php?page=" . $redirectPage;
                    if (!empty($redirectSearch)) {
                        $redirectUrl .= "&search=" . urlencode($redirectSearch);
                    }
                    if (!empty($redirectStatus)) {
                        $redirectUrl .= "&status_filter=" . urlencode($redirectStatus);
                    }
                    $redirectUrl .= "&message=" . urlencode($message) . "&type=" . $messageType;
                    
                    header("Location: " . $redirectUrl);
                    exit();
                } else {
                    $message = "Error: " . $conn->error;
                    $messageType = "danger";
                }
            }
        } else {
            $message = "Data tidak ditemukan!";
            $messageType = "danger";
        }
    }
}

// Search functionality
$search = isset($_GET['search']) ? $conn->real_escape_string($_GET['search']) : '';
$status_filter = isset($_GET['status_filter']) ? $_GET['status_filter'] : '';

// Pagination
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$records_per_page = 10;
$offset = ($page - 1) * $records_per_page;

// Handle due filter
$due_filter = isset($_GET['due_filter']) ? $_GET['due_filter'] : '';

// Build base query for counting with role-based access
$countSql = "SELECT COUNT(*) as total FROM sales_visit sv 
             LEFT JOIN users u_created ON sv.created_by = u_created.id 
             LEFT JOIN users u_updated ON sv.updated_by = u_updated.id 
             WHERE 1=1";

// Role-based filtering
if ($user['role'] === 'sales') {
    $countSql .= " AND sv.created_by = " . intval($_SESSION['user_id']);
}

$params = [];
$types = '';

if (!empty($search)) {
    $countSql .= " AND (sv.id_pelanggan LIKE ? OR sv.nama LIKE ? OR sv.alamat LIKE ? OR sv.hid LIKE ? OR sv.no_hp LIKE ? OR sv.email LIKE ?)";
    $searchParam = "%$search%";
    for ($i = 0; $i < 6; $i++) {
        $params[] = $searchParam;
        $types .= 's';
    }
}

if (!empty($status_filter)) {
    $countSql .= " AND sv.status = ?";
    $params[] = $status_filter;
    $types .= 's';
}

// Add due date filtering
if (!empty($due_filter)) {
    switch ($due_filter) {
        case 'due_today':
            $countSql .= " AND DATE(sv.jatuh_tempo_pemasangan) = CURDATE()";
            break;
        case 'overdue':
            $countSql .= " AND DATE(sv.jatuh_tempo_pemasangan) < CURDATE() AND sv.status IN ('Request')";
            break;
        case 'due_week':
            $countSql .= " AND DATE(sv.jatuh_tempo_pemasangan) BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 7 DAY)";
            break;
    }
}

// Get total records
$countStmt = $conn->prepare($countSql);
if (!empty($params)) {
    $countStmt->bind_param($types, ...$params);
}
$countStmt->execute();
$totalRecords = $countStmt->get_result()->fetch_assoc()['total'];
$totalPages = ceil($totalRecords / $records_per_page);

// Build main query with pagination and role-based access
$sql = "SELECT sv.*, 
        u_created.full_name as created_by_name, 
        u_updated.full_name as updated_by_name 
        FROM sales_visit sv 
        LEFT JOIN users u_created ON sv.created_by = u_created.id 
        LEFT JOIN users u_updated ON sv.updated_by = u_updated.id 
        WHERE 1=1";

// Role-based filtering  
if ($user['role'] === 'sales') {
    $sql .= " AND sv.created_by = " . intval($_SESSION['user_id']);
}

$params = []; // Reset params for main query
$types = '';

if (!empty($search)) {
    $sql .= " AND (sv.id_pelanggan LIKE ? OR sv.nama LIKE ? OR sv.alamat LIKE ? OR sv.hid LIKE ? OR sv.no_hp LIKE ? OR sv.email LIKE ?)";
    $searchParam = "%$search%";
    for ($i = 0; $i < 6; $i++) {
        $params[] = $searchParam;
        $types .= 's';
    }
}

if (!empty($status_filter)) {
    $sql .= " AND sv.status = ?";
    $params[] = $status_filter;
    $types .= 's';
}

// Add due date filtering for main query
if (!empty($due_filter)) {
    switch ($due_filter) {
        case 'due_today':
            $sql .= " AND DATE(sv.jatuh_tempo_pemasangan) = CURDATE()";
            break;
        case 'overdue':
            $sql .= " AND DATE(sv.jatuh_tempo_pemasangan) < CURDATE() AND sv.status IN ('Request')";
            break;
        case 'due_week':
            $sql .= " AND DATE(sv.jatuh_tempo_pemasangan) BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 7 DAY)";
            break;
    }
}

$sql .= " ORDER BY sv.tanggal_input DESC LIMIT ? OFFSET ?";
$params[] = $records_per_page;
$params[] = $offset;
$types .= 'ii';

$stmt = $conn->prepare($sql);
if (!empty($params)) {
    $stmt->bind_param($types, ...$params);
}
$stmt->execute();
$result = $stmt->get_result();

// Get data for edit with permission check
$editData = null;
if (isset($_GET['edit'])) {
    $editId = $_GET['edit'];
    
    // Base query
    $editSql = "SELECT sv.*, u_created.full_name as created_by_name 
                FROM sales_visit sv 
                LEFT JOIN users u_created ON sv.created_by = u_created.id 
                WHERE sv.id = ?";
    
    // Add role-based restriction for sales users
    if ($user['role'] === 'sales') {
        $editSql .= " AND sv.created_by = ?";
        $editStmt = $conn->prepare($editSql);
        $editStmt->bind_param("ii", $editId, $_SESSION['user_id']);
    } else {
        $editStmt = $conn->prepare($editSql);
        $editStmt->bind_param("i", $editId);
    }
    
    $editStmt->execute();
    $editResult = $editStmt->get_result();
    
    if ($editResult->num_rows > 0) {
        $editData = $editResult->fetch_assoc();
    } else {
        // No permission or data not found
        header("Location: sales_visit.php?error=no_permission");
        exit();
    }
}
?>
<!-- Due Today Alert -->
        <?php
        $today = date('Y-m-d');
        $dueTodaySql = "SELECT COUNT(*) as due_count FROM sales_visit sv WHERE DATE(sv.jatuh_tempo_pemasangan) = ? AND sv.status IN ('Request', 'Connected')";
        if ($user['role'] === 'sales') {
            $dueTodaySql .= " AND sv.created_by = " . intval($_SESSION['user_id']);
        }
        $dueTodayStmt = $conn->prepare($dueTodaySql);
        $dueTodayStmt->bind_param("s", $today);
        $dueTodayStmt->execute();
        $dueTodayResult = $dueTodayStmt->get_result();
        $dueTodayCount = $dueTodayResult->fetch_assoc()['due_count'];
        ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#0d6efd">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="default">
    <meta name="apple-mobile-web-app-title" content="Sales Activity">
    <meta name="mobile-web-app-capable" content="yes">

    <!-- Manifest untuk PWA -->
    <link rel="manifest" href="./manifest.json">

    <!-- Icons untuk PWA -->
    <link rel="apple-touch-icon" href="./icons/icon-192.png">
    <link rel="icon" type="image/png" sizes="192x192" href="/icons/icon-192.png">
    <link rel="icon" type="image/png" sizes="512x512" href="/icons/icon-512.png">
    <title>Sales Activity Management</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .nav-link { color: #333; }
        .nav-link:hover { color: #666; }
        .sticky-row {
            position: sticky;
            top: 0;
            background-color: white;
            z-index: 1;
        }
        .notification-dropdown {
            min-width: 350px;
            max-height: 400px;
            overflow-y: auto;
        }
        .notification-item {
            border-bottom: 1px solid #eee;
            padding: 10px;
            cursor: pointer;
        }
        .notification-item:hover {
            background-color: #f8f9fa;
        }
        .notification-item.unread {
            background-color: #e3f2fd;
            border-left: 4px solid #2196f3;
        }
        .notification-badge {
            position: absolute;
            top: -5px;
            right: -5px;
            background: #dc3545;
            color: white;
            border-radius: 50%;
            padding: 2px 6px;
            font-size: 0.75rem;
            min-width: 18px;
            text-align: center;
        }
        .due-today-alert {
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(220, 53, 69, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(220, 53, 69, 0); }
            100% { box-shadow: 0 0 0 0 rgba(220, 53, 69, 0); }
        }
    </style>
    <style>
        .nav-link { color: #333; }
        .nav-link:hover { color: #666; }
        .welcome-section { background-color: #f8f9fa; }
        .sticky-row {
            position: sticky;
            top: 0;
            background-color: white;
            z-index: 1;
        }
        .modal-lg { max-width: 900px; }
    </style>

    <!-- Tambahkan script ini di bagian <head> atau sebelum </body> di sales_visit.php -->

<!-- Service Worker Registration Script -->
<script>
// Fixed Service Worker Integration Script untuk sales_visit.php
// Perbaikan untuk DOM manipulation errors

// Check if browser supports Service Workers and Push Notifications
if ('serviceWorker' in navigator && 'PushManager' in window) {
    
    // Register Service Worker
    navigator.serviceWorker.register('./sw.js')
        .then(function(registration) {
            console.log('Service Worker registered successfully:', registration.scope);
            
            // Request permission for notifications after page load
            setTimeout(function() {
                requestNotificationPermission(registration);
            }, 3000);
            
            // Setup periodic notification check
            setupNotificationCheck(registration);
            
        })
        .catch(function(error) {
            console.error('Service Worker registration failed:', error);
        });
    
} else {
    console.warn('Service Workers or Push Notifications not supported');
    setupFallbackNotification();
}
// 3. Handle User ID mismatch
function handleUserIdMismatch(errorData) {
    console.log('🔧 Handling User ID mismatch...');
    console.log('Session User ID:', errorData.debug_info?.session_user_id);
    console.log('Provided User ID:', errorData.debug_info?.provided_user_id);
    
    // Show user-friendly message
    if (typeof showToast === 'function') {
        showToast('🔄 Memperbaiki masalah session... Silakan refresh halaman.', 'warning');
    }
    
    // Suggest page refresh after delay
    setTimeout(() => {
        if (confirm('Ada masalah dengan session data. Refresh halaman untuk memperbaikinya?')) {
            window.location.reload();
        }
    }, 3000);
}

// 4. Handle authentication error
function handleAuthenticationError() {
    if (typeof showToast === 'function') {
        showToast('❌ Session expired. Redirecting to login...', 'error');
    }
    
    setTimeout(() => {
        window.location.href = 'login.php';
    }, 2000);
}

// 5. Enhanced checkForDueVisits function
function checkForDueVisits() {
    const url = `check_notifications.php?type=quick&user_id=${CURRENT_USER_ID}`;
    
    fetch(url, {
        method: 'GET',
        credentials: 'same-origin'
    })
    .then(function(response) {
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        return response.json();
    })
    .then(function(data) {
        if (data.success) {
            console.log('✅ Notification check successful:', data);
            
            // Update page indicators
            if (typeof updatePageIndicators === 'function') {
                updatePageIndicators(data);
            }
            
            // Show local notification if needed
            if ((data.due_today > 0 || data.overdue > 0)) {
                if (typeof shouldShowNotification === 'function' && shouldShowNotification(data)) {
                    if (typeof showLocalNotification === 'function') {
                        showLocalNotification(data);
                    }
                }
            }
        } else {
            console.error('❌ Notification check failed:', data.error);
            
            // Handle authentication errors
            if (data.error.includes('Access denied') || data.error.includes('not authenticated')) {
                handleAuthenticationError();
            }
        }
    })
    .catch(function(error) {
        console.log('⚠️ Notification check failed:', error.message);
        
        // Don't show error to user for network issues - just log it
        console.log('This is usually temporary - will retry on next interval');
    });
}

// 6. Simple session validation (without additional files)
function validateCurrentSession() {
    console.log('🔍 Validating current session...');
    
    // Use existing endpoint to validate session
    fetch(`check_notifications.php?type=quick&user_id=${CURRENT_USER_ID}`, {
        method: 'GET',
        credentials: 'same-origin'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            console.log('✅ Session is valid');
            console.log('User role:', data.user_role);
            console.log('Due today:', data.due_today);
            console.log('Overdue:', data.overdue);
            
            // Store session validation time
            localStorage.setItem('lastSessionValidation', Date.now().toString());
        } else {
            console.log('❌ Session validation failed:', data.error);
            
            if (data.error.includes('Access denied')) {
                handleAuthenticationError();
            }
        }
    })
    .catch(error => {
        console.log('⚠️ Session validation error:', error.message);
    });
}

// 7. Test functions for debugging
function testCurrentUserId() {
    console.log('🧪 Testing current user ID...');
    console.log('CURRENT_USER_ID:', CURRENT_USER_ID);
    console.log('Type:', typeof CURRENT_USER_ID);
    
    // Test with check_notifications endpoint
    fetch(`check_notifications.php?type=quick&user_id=${CURRENT_USER_ID}`)
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                console.log('✅ User ID is valid');
                console.log('User role:', data.user_role);
                console.log('Due today:', data.due_today);
                console.log('Overdue:', data.overdue);
            } else {
                console.log('❌ User ID test failed:', data.error);
            }
        })
        .catch(error => {
            console.error('❌ User ID test error:', error);
        });
}

function testSubscriptionSave() {
    console.log('🧪 Testing subscription save...');
    
    const mockSubscription = {
        endpoint: 'https://fcm.googleapis.com/fcm/send/test-endpoint-' + Date.now(),
        keys: {
            p256dh: 'test-p256dh-key-' + Math.random().toString(36).substr(2, 9),
            auth: 'test-auth-key-' + Math.random().toString(36).substr(2, 9)
        }
    };
    
    const payload = {
        subscription: mockSubscription,
        user_id: CURRENT_USER_ID,
        user_agent: navigator.userAgent,
        timestamp: Date.now()
    };
    
    fetch('save_subscription.php?debug=1', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
    .then(response => response.text())
    .then(text => {
        console.log('Test response:', text);
        
        try {
            const data = JSON.parse(text);
            if (data.success) {
                console.log('✅ Test subscription successful!');
                console.log('Action:', data.action);
                console.log('Device:', data.device_info);
            } else {
                console.log('❌ Test subscription failed:', data.error);
                console.log('Debug info:', data.debug_info);
            }
        } catch (e) {
            console.log('❌ Test response not JSON');
        }
    })
    .catch(error => {
        console.error('❌ Test subscription error:', error);
    });
}

// 8. Auto-fix initialization
function initializeUserIdFix() {
    console.log('🚀 Initializing User ID fix...');
    console.log('Current User ID:', CURRENT_USER_ID, 'Type:', typeof CURRENT_USER_ID);
    
    // Validate session immediately
    validateCurrentSession();
    
    // Override existing functions if they exist
    if (typeof window.originalSendSubscriptionToServer === 'undefined' && typeof window.sendSubscriptionToServer === 'function') {
        window.originalSendSubscriptionToServer = window.sendSubscriptionToServer;
    }
    window.sendSubscriptionToServer = sendSubscriptionToServer;
    
    if (typeof window.originalCheckForDueVisits === 'undefined' && typeof window.checkForDueVisits === 'function') {
        window.originalCheckForDueVisits = window.checkForDueVisits;
    }
    window.checkForDueVisits = checkForDueVisits;
    
    // Add test functions to window for debugging
    window.testCurrentUserId = testCurrentUserId;
    window.testSubscriptionSave = testSubscriptionSave;
    window.validateCurrentSession = validateCurrentSession;
    
    console.log('✅ User ID fix initialized');
    console.log('Debug functions available: testCurrentUserId(), testSubscriptionSave(), validateCurrentSession()');
}

// 9. Periodic session validation
function setupPeriodicValidation() {
    // Validate session every 10 minutes
    setInterval(() => {
        const lastValidation = localStorage.getItem('lastSessionValidation');
        const now = Date.now();
        
        // Only validate if more than 10 minutes since last validation
        if (!lastValidation || (now - parseInt(lastValidation)) > 10 * 60 * 1000) {
            validateCurrentSession();
        }
    }, 10 * 60 * 1000); // 10 minutes
}

// 10. Initialize everything when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    console.log('🔧 Initializing standalone User ID fix...');
    
    // Initialize fixes
    initializeUserIdFix();
    
    // Setup periodic validation
    setupPeriodicValidation();
    
    // Test user ID after short delay
    setTimeout(testCurrentUserId, 2000);
});

// 11. Global error handler for User ID issues
window.addEventListener('unhandledrejection', function(event) {
    if (event.reason && event.reason.message && event.reason.message.includes('User ID mismatch')) {
        console.log('🔧 Detected User ID mismatch in promise rejection');
        handleUserIdMismatch({ error: event.reason.message });
    }
});

console.log('✅ Standalone User ID fix script loaded');
console.log('Available functions: testCurrentUserId(), testSubscriptionSave(), validateCurrentSession()');
// Fixed function to update page indicators
function updatePageIndicators(data) {
    try {
        // Update notification badge in navbar
        updateNotificationBadge(data);
        
        // Update page title with due count
        updatePageTitle(data);
        
        // Update due today alert
        updateDueTodayAlert(data);
        
        // Store last check data
        localStorage.setItem('lastNotificationCheck', JSON.stringify({
            data: data,
            timestamp: Date.now()
        }));
        
    } catch (error) {
        console.error('Error updating page indicators:', error);
    }
}

// Separate function for notification badge
function updateNotificationBadge(data) {
    try {
        const bellButton = document.querySelector('#notificationDropdown');
        const existingBadge = document.querySelector('.notification-badge');
        const totalUrgent = data.total_urgent || 0;
        
        if (totalUrgent > 0) {
            if (!existingBadge && bellButton) {
                // Create new badge
                const badge = document.createElement('span');
                badge.className = 'notification-badge';
                badge.textContent = totalUrgent;
                bellButton.appendChild(badge);
            } else if (existingBadge) {
                // Update existing badge
                existingBadge.textContent = totalUrgent;
                existingBadge.style.display = 'inline-block';
            }
        } else if (existingBadge) {
            // Hide badge if no urgent notifications
            existingBadge.style.display = 'none';
        }
    } catch (error) {
        console.error('Error updating notification badge:', error);
    }
}

// Separate function for page title
function updatePageTitle(data) {
    try {
        const originalTitle = 'Sales Activity Management';
        const totalUrgent = data.total_urgent || 0;
        
        if (totalUrgent > 0) {
            document.title = `(${totalUrgent}) ${originalTitle}`;
        } else {
            document.title = originalTitle;
        }
    } catch (error) {
        console.error('Error updating page title:', error);
    }
}

// Fixed function to update due today alert
function updateDueTodayAlert(data) {
    try {
        const existingAlert = document.querySelector('.due-today-alert');
        const totalUrgent = data.due_today + data.overdue;
        
        if (totalUrgent > 0) {
            if (!existingAlert) {
                // Create new alert
                createDueTodayAlert(data);
            } else {
                // Update existing alert
                updateExistingAlert(existingAlert, data);
            }
        } else if (existingAlert) {
            // Remove alert if no due items
            safeRemoveElement(existingAlert);
        }
    } catch (error) {
        console.error('Error updating due today alert:', error);
    }
}

// Safe function to create due today alert
function createDueTodayAlert(data) {
    try {
        const container = document.querySelector('.container');
        if (!container) return;
        
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-danger due-today-alert d-flex align-items-center mb-4';
        alertDiv.setAttribute('role', 'alert');
        
        const urgencyIcon = data.overdue > 0 ? 'fas fa-exclamation-triangle' : 'fas fa-clock';
        const urgencyText = data.overdue > 0 ? 'Urgent!' : 'Reminder!';
        
        let message = '';
        if (data.overdue > 0 && data.due_today > 0) {
            message = `${data.overdue} sales visit overdue dan ${data.due_today} jatuh tempo hari ini!`;
        } else if (data.overdue > 0) {
            message = `${data.overdue} sales visit sudah melewati batas waktu!`;
        } else {
            message = `${data.due_today} sales visit jatuh tempo hari ini!`;
        }
        
        alertDiv.innerHTML = `
            <i class="${urgencyIcon} me-2"></i>
            <div class="flex-grow-1">
                <strong>${urgencyText}</strong> ${message}
            </div>
            <button type="button" class="btn btn-light btn-sm me-2" onclick="showDueFilter('${data.overdue > 0 ? 'overdue' : 'due_today'}')">
                <i class="fas fa-eye me-1"></i>Lihat
            </button>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        // Find safe insertion point
        const insertionPoint = findSafeInsertionPoint(container);
        if (insertionPoint) {
            container.insertBefore(alertDiv, insertionPoint);
        } else {
            container.appendChild(alertDiv);
        }
        
    } catch (error) {
        console.error('Error creating due today alert:', error);
    }
}

// Find safe insertion point in container
function findSafeInsertionPoint(container) {
    try {
        // Try to find h1 first
        const h1 = container.querySelector('h1');
        if (h1 && h1.nextSibling) {
            return h1.nextSibling;
        }
        
        // Try to find first div with mb-4 class
        const firstDiv = container.querySelector('div.mb-4');
        if (firstDiv) {
            return firstDiv;
        }
        
        // Try to find first child that's not a script
        const children = container.children;
        for (let i = 0; i < children.length; i++) {
            if (children[i].tagName !== 'SCRIPT') {
                return children[i];
            }
        }
        
        return null;
    } catch (error) {
        console.error('Error finding insertion point:', error);
        return null;
    }
}

// Update existing alert content
function updateExistingAlert(alertElement, data) {
    try {
        const urgencyIcon = data.overdue > 0 ? 'fas fa-exclamation-triangle' : 'fas fa-clock';
        const urgencyText = data.overdue > 0 ? 'Urgent!' : 'Reminder!';
        
        let message = '';
        if (data.overdue > 0 && data.due_today > 0) {
            message = `${data.overdue} sales visit overdue dan ${data.due_today} jatuh tempo hari ini!`;
        } else if (data.overdue > 0) {
            message = `${data.overdue} sales visit sudah melewati batas waktu!`;
        } else {
            message = `${data.due_today} sales visit jatuh tempo hari ini!`;
        }
        
        alertElement.innerHTML = `
            <i class="${urgencyIcon} me-2"></i>
            <div class="flex-grow-1">
                <strong>${urgencyText}</strong> ${message}
            </div>
            <button type="button" class="btn btn-light btn-sm me-2" onclick="showDueFilter('${data.overdue > 0 ? 'overdue' : 'due_today'}')">
                <i class="fas fa-eye me-1"></i>Lihat
            </button>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
    } catch (error) {
        console.error('Error updating existing alert:', error);
    }
}

// Safe element removal function
function safeRemoveElement(element) {
    try {
        if (element && element.parentNode) {
            element.parentNode.removeChild(element);
        }
    } catch (error) {
        console.error('Error removing element:', error);
    }
}

// Enhanced function to determine if notification should be shown
function shouldShowNotification(data) {
    if (Notification.permission !== 'granted') {
        return false;
    }
    
    if (document.visibilityState === 'visible') {
        return false;
    }
    
    const lastNotificationTime = localStorage.getItem('lastLocalNotificationTime');
    const now = Date.now();
    
    if (lastNotificationTime && (now - parseInt(lastNotificationTime)) < 15 * 60 * 1000) {
        return false;
    }
    
    const lastCheck = localStorage.getItem('lastNotificationCheck');
    if (lastCheck) {
        try {
            const lastData = JSON.parse(lastCheck).data;
            if (lastData.due_today === data.due_today && lastData.overdue === data.overdue) {
                return false;
            }
        } catch (e) {
            // Ignore parsing errors
        }
    }
    
    return true;
}

// Enhanced local notification function
function showLocalNotification(data) {
    if (!shouldShowNotification(data)) {
        return;
    }
    
    let title = 'Sales Activity Alert';
    let body = '';
    let icon = '/icons/icon-192.png';
    let urgency = 'normal';
    let tag = 'sales-visit-' + Date.now();
    
    if (data.overdue > 0 && data.due_today > 0) {
        title = '🚨 Urgent: Multiple Due Visits';
        body = `${data.overdue} overdue dan ${data.due_today} jatuh tempo hari ini`;
        urgency = 'high';
        tag = 'sales-visit-urgent';
    } else if (data.overdue > 0) {
        title = '⚠️ Overdue Sales Visits';
        body = `${data.overdue} sales visit sudah melewati batas waktu`;
        urgency = 'high';
        tag = 'sales-visit-overdue';
    } else if (data.due_today > 0) {
        title = '📅 Due Today Reminder';
        body = `${data.due_today} sales visit jatuh tempo hari ini`;
        urgency = 'normal';
        tag = 'sales-visit-due-today';
    }
    
    try {
        const notification = new Notification(title, {
            body: body,
            icon: icon,
            badge: '/icons/badge.png',
            tag: tag,
            requireInteraction: urgency === 'high',
            data: {
                url: '/sales_visit.php?due_filter=' + (data.overdue > 0 ? 'overdue' : 'due_today'),
                urgency: urgency,
                timestamp: Date.now()
            },
            vibrate: urgency === 'high' ? [200, 100, 200, 100, 200] : [200, 100, 200]
        });
        
        notification.onclick = function() {
            window.focus();
            window.location.href = this.data.url;
            notification.close();
        };
        
        setTimeout(function() {
            notification.close();
        }, urgency === 'high' ? 20000 : 10000);
        
        localStorage.setItem('lastLocalNotificationTime', Date.now().toString());
        console.log('Local notification shown:', title);
        
    } catch (error) {
        console.error('Error showing notification:', error);
    }
}

// Function to show due filter
function showDueFilter(filterType) {
    try {
        const url = new URL(window.location.href);
        url.searchParams.set('due_filter', filterType);
        url.searchParams.set('page', '1');
        window.location.href = url.toString();
    } catch (error) {
        console.error('Error in showDueFilter:', error);
        window.location.href = `sales_visit.php?due_filter=${filterType}&page=1`;
    }
}

// Enhanced setup for notification checking
function setupNotificationCheck(registration) {
    let notificationInterval;
    
    function startNotificationChecking() {
        if (notificationInterval) {
            clearInterval(notificationInterval);
        }
        
        const activeInterval = 5 * 60 * 1000;   // 5 minutes
        const inactiveInterval = 15 * 60 * 1000; // 15 minutes
        
        const currentInterval = document.visibilityState === 'visible' ? activeInterval : inactiveInterval;
        
        notificationInterval = setInterval(function() {
            if (navigator.onLine) {
                checkForDueVisits();
            }
        }, currentInterval);
    }
    
    document.addEventListener('visibilitychange', function() {
        console.log('Page visibility changed:', document.visibilityState);
        
        if (document.visibilityState === 'visible') {
            checkForDueVisits();
            startNotificationChecking();
        } else {
            startNotificationChecking();
        }
    });
    
    window.addEventListener('online', function() {
        console.log('Connection restored - checking notifications');
        checkForDueVisits();
        startNotificationChecking();
    });
    
    window.addEventListener('offline', function() {
        console.log('Connection lost - pausing notification checks');
        if (notificationInterval) {
            clearInterval(notificationInterval);
        }
    });
    
    startNotificationChecking();
    setTimeout(checkForDueVisits, 30000);
}

// Enhanced permission request function
function requestNotificationPermission(registration) {
    if (!('Notification' in window)) {
        console.warn('Notifications not supported');
        return;
    }
    
    if (sessionStorage.getItem('notificationPromptDismissed') === 'true') {
        return;
    }
    
    if (Notification.permission === 'default') {
        <?php if ($dueTodayCount > 0 || $user['role'] === 'sales'): ?>
        showPermissionDialog(registration);
        <?php endif; ?>
    } else if (Notification.permission === 'granted') {
        console.log('Notification permission already granted');
        subscribeToPushNotifications(registration);
    } else {
        console.log('Notification permission denied');
        showNotificationDeniedInfo();
    }
}

// Safe function to show notification denied info
function showNotificationDeniedInfo() {
    try {
        const container = document.querySelector('.container');
        if (container && !document.querySelector('.notification-denied-info')) {
            const infoDiv = document.createElement('div');
            infoDiv.className = 'alert alert-info notification-denied-info d-flex align-items-center mb-3';
            infoDiv.innerHTML = `
                <i class="fas fa-info-circle me-2"></i>
                <div class="flex-grow-1">
                    <strong>Tip:</strong> Aktifkan notifikasi browser untuk mendapat peringatan sales visit yang jatuh tempo.
                </div>
                <button type="button" class="btn btn-sm btn-outline-primary" onclick="showNotificationSettings()">
                    Cara Aktifkan
                </button>
                <button type="button" class="btn-close ms-2" data-bs-dismiss="alert"></button>
            `;
            
            // Safe insertion
            const insertionPoint = findSafeInsertionPoint(container);
            if (insertionPoint) {
                container.insertBefore(infoDiv, insertionPoint);
            } else {
                container.appendChild(infoDiv);
            }
        }
    } catch (error) {
        console.error('Error showing notification denied info:', error);
    }
}

// Enhanced permission dialog
function showPermissionDialog(registration) {
    try {
        // Remove existing modal if any
        const existingModal = document.getElementById('permissionModal');
        if (existingModal) {
            safeRemoveElement(existingModal);
        }
        
        const permissionModal = `
            <div id="permissionModal" class="modal fade" tabindex="-1" data-bs-backdrop="static">
                <div class="modal-dialog modal-dialog-centered">
                    <div class="modal-content">
                        <div class="modal-header bg-primary text-white">
                            <h5 class="modal-title">
                                <i class="fas fa-bell me-2"></i>
                                Aktifkan Notifikasi Sales Activity
                            </h5>
                        </div>
                        <div class="modal-body">
                            <div class="text-center mb-3">
                                <i class="fas fa-bell fa-3x text-primary mb-3"></i>
                            </div>
                            <p class="text-center mb-3">Dapatkan peringatan otomatis untuk:</p>
                            <ul class="list-unstyled">
                                <li class="mb-2">
                                    <i class="fas fa-exclamation-triangle text-danger me-2"></i>
                                    <strong>Sales visit overdue</strong> - Sudah melewati batas waktu
                                </li>
                                <li class="mb-2">
                                    <i class="fas fa-clock text-warning me-2"></i>
                                    <strong>Jatuh tempo hari ini</strong> - Perlu segera ditindaklanjuti
                                </li>
                                <li class="mb-2">
                                    <i class="fas fa-calendar-alt text-info me-2"></i>
                                    <strong>Reminder pemasangan</strong> - Dalam 1 minggu ke depan
                                </li>
                            </ul>
                            
                            <?php if ($dueTodayCount > 0): ?>
                            <div class="alert alert-warning">
                                <i class="fas fa-exclamation-triangle me-2"></i>
                                <strong>Penting!</strong> Anda memiliki <?php echo $dueTodayCount; ?> sales visit yang jatuh tempo hari ini.
                            </div>
                            <?php endif; ?>
                            
                            <div class="alert alert-info">
                                <i class="fas fa-info-circle me-2"></i>
                                Notifikasi hanya akan muncul untuk hal-hal penting. Anda dapat mengubah pengaturan kapan saja.
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" onclick="dismissPermissionRequest()">
                                <i class="fas fa-times me-1"></i>Tidak Sekarang
                            </button>
                            <button type="button" class="btn btn-primary btn-lg" onclick="enableNotifications()">
                                <i class="fas fa-bell me-1"></i>Aktifkan Notifikasi
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', permissionModal);
        const modal = new bootstrap.Modal(document.getElementById('permissionModal'));
        modal.show();
        
        window.swRegistration = registration;
        
    } catch (error) {
        console.error('Error showing permission dialog:', error);
    }
}

// Enhanced enable notifications function
function enableNotifications() {
    const enableBtn = document.querySelector('button[onclick="enableNotifications()"]');
    if (enableBtn) {
        enableBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Memproses...';
        enableBtn.disabled = true;
    }
    
    Notification.requestPermission().then(function(permission) {
        if (permission === 'granted') {
            console.log('Notification permission granted');
            subscribeToPushNotifications(window.swRegistration);
            
            const modal = bootstrap.Modal.getInstance(document.getElementById('permissionModal'));
            if (modal) modal.hide();
            
            showToast('🎉 Notifikasi berhasil diaktifkan! Anda akan mendapat peringatan otomatis.', 'success');
            
            setTimeout(function() {
                if (Notification.permission === 'granted') {
                    new Notification('✅ Sales Activity Notifications Active', {
                        body: 'Sistem notifikasi sudah aktif. Anda akan mendapat peringatan untuk sales visit yang jatuh tempo.',
                        icon: './icons/icon-192.png',
                        tag: 'welcome-notification'
                    });
                }
            }, 2000);
            
            const deniedInfo = document.querySelector('.notification-denied-info');
            if (deniedInfo) {
                safeRemoveElement(deniedInfo);
            }
            
        } else {
            console.log('Notification permission denied');
            showToast('Notifikasi ditolak. Anda bisa mengaktifkannya nanti melalui pengaturan browser.', 'warning');
            setTimeout(showNotificationSettings, 1000);
        }
    }).catch(function(error) {
        console.error('Error requesting notification permission:', error);
        showToast('Terjadi kesalahan saat meminta izin notifikasi.', 'error');
    }).finally(function() {
        if (enableBtn) {
            enableBtn.innerHTML = '<i class="fas fa-bell me-1"></i>Aktifkan Notifikasi';
            enableBtn.disabled = false;
        }
    });
}

// Enhanced dismiss function
function dismissPermissionRequest() {
    try {
        const modal = bootstrap.Modal.getInstance(document.getElementById('permissionModal'));
        if (modal) modal.hide();
        
        sessionStorage.setItem('notificationPromptDismissed', 'true');
        showToast('💡 Tip: Anda dapat mengaktifkan notifikasi kapan saja melalui pengaturan browser.', 'info');
        
        setTimeout(showNotificationDeniedInfo, 3000);
    } catch (error) {
        console.error('Error dismissing permission request:', error);
    }
}

// Show notification settings guide
function showNotificationSettings() {
    try {
        const existingModal = document.getElementById('notificationSettingsModal');
        if (existingModal) {
            safeRemoveElement(existingModal);
        }
        
        const modal = `
            <div id="notificationSettingsModal" class="modal fade" tabindex="-1">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">
                                <i class="fas fa-cog me-2"></i>Cara Mengaktifkan Notifikasi
                            </h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <div class="mb-3">
                                <h6><i class="fab fa-chrome me-2"></i>Chrome/Edge:</h6>
                                <ol class="small">
                                    <li>Klik ikon <i class="fas fa-lock"></i> di address bar</li>
                                    <li>Pilih "Notifications" → "Allow"</li>
                                    <li>Refresh halaman</li>
                                </ol>
                            </div>
                            <div class="mb-3">
                                <h6><i class="fab fa-firefox me-2"></i>Firefox:</h6>
                                <ol class="small">
                                    <li>Klik ikon <i class="fas fa-shield-alt"></i> di address bar</li>
                                    <li>Pilih "Permissions" → "Notifications" → "Allow"</li>
                                    <li>Refresh halaman</li>
                                </ol>
                            </div>
                            <div class="alert alert-info">
                                <i class="fas fa-mobile-alt me-2"></i>
                                <strong>Mobile:</strong> Notifikasi bekerja di Chrome/Firefox mobile.
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Tutup</button>
                            <button type="button" class="btn btn-primary" onclick="retryNotificationPermission()">Coba Lagi</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', modal);
        const modalElement = new bootstrap.Modal(document.getElementById('notificationSettingsModal'));
        modalElement.show();
        
    } catch (error) {
        console.error('Error showing notification settings:', error);
    }
}

// Retry notification permission
function retryNotificationPermission() {
    try {
        if (window.swRegistration) {
            sessionStorage.removeItem('notificationPromptDismissed');
            requestNotificationPermission(window.swRegistration);
        }
        
        const modal = bootstrap.Modal.getInstance(document.getElementById('notificationSettingsModal'));
        if (modal) modal.hide();
    } catch (error) {
        console.error('Error retrying notification permission:', error);
    }
}

// Push subscription function
function subscribeToPushNotifications(registration) {
    if (!registration.pushManager) {
        console.warn('Push notifications not supported');
        return;
    }
    
    const applicationServerKey = 'BEl62iUYgUivyIlOkZ-qPt8-FkXG1JDCcSiwXKbpMeZyqNZTdCzBu4SQJAU5CPWqJq4-FqWYcNOb3gJ3wVIHTEM';
    
    registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(applicationServerKey)
    })
    .then(function(subscription) {
        console.log('Push subscription successful:', subscription);
        sendSubscriptionToServer(subscription);
    })
    .catch(function(error) {
        console.error('Push subscription failed:', error);
        showToast('❌ Gagal mengaktifkan push notifications. Notifikasi lokal tetap akan bekerja.', 'warning');  
    });
}

// 1. Get current user ID from PHP session
const CURRENT_USER_ID = <?php echo $_SESSION['user_id']; ?>;

// 2. Enhanced sendSubscriptionToServer function
function sendSubscriptionToServer(subscription) {
    console.log('🔄 Sending subscription to server...');
    console.log('Current User ID:', CURRENT_USER_ID, 'Type:', typeof CURRENT_USER_ID);
    
    const payload = {
        subscription: subscription,
        user_id: CURRENT_USER_ID, // Use dynamic user ID
        user_agent: navigator.userAgent,
        timestamp: Date.now()
    };
    
    fetch('save_subscription.php', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload)
    })
    .then(function(response) {
        console.log('Response status:', response.status);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        return response.text();
    })
    .then(function(text) {
        console.log('Raw response:', text.substring(0, 200) + '...');
        
        try {
            const data = JSON.parse(text);
            
            if (data.success) {
                console.log('✅ Subscription saved successfully');
                console.log('Action:', data.action);
                console.log('Device:', data.device_info);
                console.log('User:', data.user_name);
                
                localStorage.setItem('pushNotificationEnabled', 'true');
                localStorage.setItem('pushSubscriptionTime', Date.now().toString());
                
                if (typeof showToast === 'function') {
                    showToast('✅ Push notifications berhasil diaktifkan!', 'success');
                }
            } else {
                console.error('❌ Server error:', data.error);
                console.log('Debug info:', data.debug_info);
                
                // Handle specific errors
                if (data.error.includes('User ID mismatch')) {
                    console.log('🔧 User ID mismatch detected - attempting auto-fix...');
                    handleUserIdMismatch(data);
                } else if (data.error.includes('not authenticated')) {
                    console.log('🔧 Authentication error - redirecting to login...');
                    handleAuthenticationError();
                } else {
                    if (typeof showToast === 'function') {
                        showToast(`❌ Error: ${data.error}`, 'error');
                    }
                }
            }
        } catch (parseError) {
            console.error('❌ JSON parse error:', parseError);
            console.log('Response was not valid JSON');
            
            if (typeof showToast === 'function') {
                showToast('❌ Server response error', 'error');
            }
        }
    })
    .catch(function(error) {
        console.error('❌ Network error:', error);
        
        if (typeof showToast === 'function') {
            showToast(`❌ Network error: ${error.message}`, 'error');
        }
    });
}
// Fallback notification system
function setupFallbackNotification() {
    console.log('Using fallback notification system');
    
    setInterval(function() {
        if (document.visibilityState === 'visible' && navigator.onLine) {
            checkForDueVisits();
        }
    }, 15 * 60 * 1000);
    
    setTimeout(function() {
        showToast('ℹ️ Browser Anda tidak mendukung notifikasi push. Sistem akan menggunakan pemeriksaan berkala.', 'info');
    }, 5000);
}

// Utility function to convert VAPID key
function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding)
        .replace(/\-/g, '+')
        .replace(/_/g, '/');
        
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    
    return outputArray;
}

// Enhanced toast function
function showToast(message, type) {
    try {
        const existingToast = document.getElementById('dynamicToast');
        if (existingToast) {
            safeRemoveElement(existingToast);
        }
        
        const icons = {
            success: 'fas fa-check-circle',
            error: 'fas fa-exclamation-triangle',
            warning: 'fas fa-exclamation-circle',
            info: 'fas fa-info-circle'
        };
        
        const colors = {
            success: 'success',
            error: 'danger',
            warning: 'warning',
            info: 'info'
        };
        
        const icon = icons[type] || icons.info;
        const color = colors[type] || colors.info;
        
        const toast = document.createElement('div');
        toast.id = 'dynamicToast';
        toast.className = `alert alert-${color} alert-dismissible fade show position-fixed`;
        
        toast.style.cssText = `
            top: 20px; right: 20px; z-index: 9999;
            min-width: 350px; max-width: 500px;
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
            border-radius: 12px;
            border-left: 4px solid var(--bs-${color});
        `;
        
        toast.innerHTML = `
            <div class="d-flex align-items-start">
                <i class="${icon} me-3 mt-1"></i>
                <div class="flex-grow-1">${message}</div>
                <button type="button" class="btn-close ms-2" data-bs-dismiss="alert"></button>
            </div>
        `;
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            if (toast && toast.parentNode) {
                safeRemoveElement(toast);
            }
        }, 6000);
        
    } catch (error) {
        console.error('Toast error:', error);
        // Fallback to alert
        alert(message.replace(/<[^>]*>?/gm, ''));
    }
}

// Debug functions
window.testNotification = function() {
    if (Notification.permission === 'granted') {
        new Notification('🧪 Test Notification', {
            body: 'Service Worker integration berhasil! Sistem notifikasi berjalan dengan baik.',
            icon: './icons/icon-192.png',
            tag: 'test-notification'
        });
        showToast('✅ Test notification berhasil dikirim!', 'success');
    } else {
        showToast('❌ Notifications not permitted. Please enable them first.', 'error');
    }
};

window.forceNotificationCheck = checkForDueVisits;
window.showNotificationSettings = showNotificationSettings;

// Safe DOM ready function
function domReady(fn) {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', fn);
    } else {
        fn();
    }
}

// Initialize when DOM is ready
domReady(function() {
    console.log('Service Worker integration initialized');
    
    // Add keyboard shortcut for testing (Ctrl+Shift+N)
    document.addEventListener('keydown', function(e) {
        if (e.ctrlKey && e.shiftKey && e.key === 'N') {
            console.log('Testing notification via keyboard shortcut...');
            window.testNotification();
        }
    });
    
    // Add notification status to page after delay
    setTimeout(function() {
        if (Notification.permission === 'denied') {
            showNotificationDeniedInfo();
        }
    }, 3000);
    
    // Handle page unload
    window.addEventListener('beforeunload', function() {
        // Clean up intervals if any
        if (typeof notificationInterval !== 'undefined' && notificationInterval) {
            clearInterval(notificationInterval);
        }
    });
});

console.log('Enhanced Service Worker integration script loaded successfully');
</script>
</head>
<body>
    <!-- Navigation Bar -->
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <div class="container">
            <a class="navbar-brand" href="#">Admin Panel</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="index.php">HID</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="dedicated.php">HID Dedicated</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" href="sales_visit.php">Sales Activity</a>
                    </li>
                    <?php if ($user['role'] === 'admin'): ?>
                    <li class="nav-item">
                        <a class="nav-link" href="user_management.php">User Management</a>
                    </li>
                    <?php endif; ?>
                    <li class="nav-item">
                        <a class="nav-link" href="change_password.php">Change Password</a>
                    </li>
                </ul>
                <div class="d-flex">
                    <!-- Notification Bell -->
                    <div class="dropdown me-3">
                        <button class="btn btn-outline-primary position-relative" type="button" id="notificationDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="fas fa-bell"></i>
                            <?php if ($unreadCount > 0): ?>
                                <span class="notification-badge"><?php echo $unreadCount; ?></span>
                            <?php endif; ?>
                        </button>
                        <div class="dropdown-menu dropdown-menu-end notification-dropdown" aria-labelledby="notificationDropdown">
                            <div class="dropdown-header d-flex justify-content-between align-items-center">
                                <span>Notifications</span>
                                <?php if ($unreadCount > 0): ?>
                                    <button class="btn btn-sm btn-link p-0" onclick="markAllAsRead()">Mark all read</button>
                                <?php endif; ?>
                            </div>
                            <div class="dropdown-divider"></div>
                            
                            <?php if (empty($notifications)): ?>
                                <div class="notification-item text-center text-muted">
                                    <i class="fas fa-inbox fa-2x mb-2"></i>
                                    <p>No notifications</p>
                                </div>
                            <?php else: ?>
                                <?php foreach ($notifications as $notification): ?>
                                    <div class="notification-item <?php echo !$notification['is_read'] ? 'unread' : ''; ?>" 
                                         data-notification-id="<?php echo $notification['id']; ?>"
                                         onclick="markAsRead(<?php echo $notification['id']; ?>)">
                                        <div class="d-flex">
                                            <div class="flex-grow-1">
                                                <h6 class="mb-1"><?php echo htmlspecialchars($notification['title']); ?></h6>
                                                <p class="mb-1 small"><?php echo htmlspecialchars($notification['message']); ?></p>
                                                <small class="text-muted"><?php echo date('d/m/Y H:i', strtotime($notification['created_at'])); ?></small>
                                            </div>
                                            <?php if (!$notification['is_read']): ?>
                                                <div class="ms-2">
                                                    <span class="badge bg-primary">New</span>
                                                </div>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            <?php endif; ?>
                            
                            <div class="dropdown-divider"></div>
                            <div class="text-center">
                                <a href="notifications.php" class="btn btn-sm btn-primary">View All</a>
                            </div>
                        </div>
                    </div>

                    <span class="navbar-text me-3">
                        Welcome, <?php echo htmlspecialchars($user['full_name']); ?>
                        <span class="badge bg-<?php echo $user['role'] == 'admin' ? 'danger' : 'info'; ?>">
                            <?php echo ucfirst($user['role']); ?>
                        </span>
                    </span>
                    <a href="logout.php" class="btn btn-outline-danger">Logout</a>
                </div>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h1>Sales Activity Management</h1>
            <div class="d-flex align-items-center">
                <span class="badge bg-<?php echo $user['role'] == 'admin' ? 'danger' : 'info'; ?> me-2">
                    <?php echo ucfirst($user['role']); ?>
                </span>
                <?php if ($user['role'] === 'sales'): ?>
                    <small class="text-muted">Viewing your data only</small>
                <?php else: ?>
                    <small class="text-muted">Viewing all data</small>
                <?php endif; ?>
            </div>
        </div>
        
        <?php if ($message): ?>
            <div class="alert alert-<?php echo $messageType; ?> alert-dismissible fade show" role="alert">
                <?php echo $message; ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <?php if (isset($_GET['error']) && $_GET['error'] == 'no_permission'): ?>
            <div class="alert alert-warning alert-dismissible fade show" role="alert">
                <i class="fas fa-exclamation-triangle me-2"></i>
                Anda tidak memiliki izin untuk mengakses data tersebut!
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        

        <?php if ($dueTodayCount > 0): ?>
            <div class="alert alert-danger due-today-alert d-flex align-items-center" role="alert">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <div class="flex-grow-1">
                    <strong>Urgent!</strong> Anda memiliki <?php echo $dueTodayCount; ?> sales visit yang jatuh tempo hari ini!
                </div>
                <button type="button" class="btn btn-light btn-sm" onclick="showDueToday()">
                    <i class="fas fa-eye me-1"></i>Lihat
                </button>
            </div>
        <?php endif; ?>

        <!-- Add New Button -->
        <div class="mb-4">
            <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#salesVisitModal" onclick="resetForm()">
                <i class="fas fa-plus"></i> Add New Sales Activity
            </button>
        </div>

        <!-- Search and Filter -->
        <div class="row mb-4">
            <div class="col-md-8">
                <form method="GET" action="" class="d-flex">
                    <input type="hidden" name="page" value="1"> <!-- Reset to page 1 when searching -->
                    <input type="text" name="search" placeholder="Search..." value="<?php echo htmlspecialchars($search); ?>" class="form-control me-2">
                    <select name="status_filter" class="form-select me-2" style="width: auto;">
                        <option value="">All Status</option>
                        <option value="Request" <?php echo $status_filter == 'Request' ? 'selected' : ''; ?>>Request</option>
                        <option value="Cancel" <?php echo $status_filter == 'Cancel' ? 'selected' : ''; ?>>Cancel</option>
                        <option value="Connected" <?php echo $status_filter == 'Connected' ? 'selected' : ''; ?>>Connected</option>
                        <option value="Disconnect" <?php echo $status_filter == 'Disconnect' ? 'selected' : ''; ?>>Disconnect</option>
                    </select>
                    <button type="submit" class="btn btn-primary">Search</button>
                </form>
            </div>
            <div class="col-md-4 text-end">
                <span class="text-muted">
                    Showing <?php echo $totalRecords > 0 ? ($offset + 1) : 0; ?> - 
                    <?php echo min($offset + $records_per_page, $totalRecords); ?> 
                    of <?php echo $totalRecords; ?> records
                </span>
            </div>
        </div>

        <!-- Data Table -->
        <div class="table-responsive">
            <table class="table table-striped table-bordered">
                <thead class="sticky-row">
                    <tr>
                        <th>Action</th>
                        <th>ID</th>
                        <th>ID Pelanggan</th>
                        <th>Nama</th>
                        <th>Alamat</th>
                        <th>HID</th>
                        <th>No HP</th>
                        <th>Email</th>
                        <th>Paket</th>
                        <th>Koordinat</th>
                        <th>Tgl Pemasangan</th>
                        <th>Jatuh Tempo</th>
                        <th>Status</th>
                        <th>Tgl Input</th>
                        <?php if ($user['role'] === 'admin'): ?>
                        <th>Input By</th>
                        <th>Update By</th>
                        <?php endif; ?>
                    </tr>
                </thead>
                <tbody>
                    <?php if ($result->num_rows > 0): ?>
                        <?php while($row = $result->fetch_assoc()): ?>
                            <tr>
                                <td>
                                    <?php
                                    // Check if user can edit/delete this record
                                    $canModify = ($user['role'] === 'admin') || ($row['created_by'] == $_SESSION['user_id']);
                                    ?>
                                    
                                    <?php if ($canModify): ?>
                                        <button class="btn btn-sm btn-warning me-1" onclick="editSalesVisit(<?php echo $row['id']; ?>)">
                                            <i class="fas fa-edit"></i>
                                        </button>
                                        <button class="btn btn-sm btn-danger" onclick="deleteSalesVisit(<?php echo $row['id']; ?>)">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    <?php else: ?>
                                        <button class="btn btn-sm btn-secondary" disabled title="No permission">
                                            <i class="fas fa-eye"></i>
                                        </button>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo htmlspecialchars($row['id']); ?></td>
                                <td><?php echo htmlspecialchars($row['id_pelanggan']); ?></td>
                                <td><?php echo htmlspecialchars($row['nama']); ?></td>
                                <td><?php echo htmlspecialchars(substr($row['alamat'], 0, 50)) . (strlen($row['alamat']) > 50 ? '...' : ''); ?></td>
                                <td><?php echo htmlspecialchars($row['hid']); ?></td>
                                <td><?php echo htmlspecialchars($row['no_hp']); ?></td>
                                <td><?php echo htmlspecialchars($row['email']); ?></td>
                                <td><?php echo htmlspecialchars($row['paket']); ?></td>
                                <td><?php echo htmlspecialchars($row['titik_koordinat']); ?></td>
                                <td><?php echo $row['tanggal_pemasangan'] ? date('d/m/Y', strtotime($row['tanggal_pemasangan'])) : '-'; ?></td>
                                <td>
                                    <?php if ($row['jatuh_tempo_pemasangan']): ?>
                                        <?php 
                                        $dueDate = strtotime($row['jatuh_tempo_pemasangan']);
                                        $today = strtotime(date('Y-m-d'));
                                        $daysDiff = ($dueDate - $today) / 86400;
                                        
                                        $class = '';
                                        $icon = '';
                                        if ($daysDiff < 0) {
                                            $class = 'text-danger fw-bold';
                                            $icon = '<i class="fas fa-exclamation-triangle"></i> ';
                                        } elseif ($daysDiff == 0) {
                                            $class = 'text-warning fw-bold';
                                            $icon = '<i class="fas fa-clock"></i> ';
                                        } elseif ($daysDiff <= 7) {
                                            $class = 'text-info';
                                            $icon = '<i class="fas fa-calendar-alt"></i> ';
                                        }
                                        ?>
                                        <span class="<?php echo $class; ?>">
                                            <?php echo $icon; ?><?php echo date('d/m/Y', strtotime($row['jatuh_tempo_pemasangan'])); ?>
                                        </span>
                                    <?php else: ?>
                                        -
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <span class="badge bg-<?php 
                                        echo $row['status'] == 'Connected' ? 'success' : 
                                            ($row['status'] == 'Cancel' ? 'danger' : 
                                            ($row['status'] == 'Disconnect' ? 'warning' : 'primary')); 
                                    ?>">
                                        <?php echo htmlspecialchars($row['status']); ?>
                                    </span>
                                </td>
                                <td><?php echo date('d/m/Y H:i', strtotime($row['tanggal_input'])); ?></td>
                                <?php if ($user['role'] === 'admin'): ?>
                                <td>
                                    <small class="text-muted">
                                        <?php echo htmlspecialchars($row['created_by_name'] ?: 'Unknown'); ?>
                                    </small>
                                </td>
                                <td>
                                    <small class="text-muted">
                                        <?php echo htmlspecialchars($row['updated_by_name'] ?: '-'); ?>
                                    </small>
                                </td>
                                <?php endif; ?>
                            </tr>
                        <?php endwhile; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="<?php echo $user['role'] === 'admin' ? '16' : '14'; ?>" class="text-center">No data found</td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

        <!-- Pagination -->
        <?php if ($totalPages > 1): ?>
            <nav aria-label="Page navigation" class="mt-4">
                <ul class="pagination justify-content-center">
                    <!-- Previous Page -->
                    <?php if ($page > 1): ?>
                        <li class="page-item">
                            <a class="page-link" href="?page=<?php echo ($page - 1); ?>&search=<?php echo urlencode($search); ?>&status_filter=<?php echo urlencode($status_filter); ?>">Previous</a>
                        </li>
                    <?php else: ?>
                        <li class="page-item disabled">
                            <span class="page-link">Previous</span>
                        </li>
                    <?php endif; ?>

                    <!-- Page Numbers -->
                    <?php
                    $start_page = max(1, $page - 2);
                    $end_page = min($totalPages, $page + 2);
                    
                    // Show first page if not in range
                    if ($start_page > 1) {
                        echo '<li class="page-item"><a class="page-link" href="?page=1&search=' . urlencode($search) . '&status_filter=' . urlencode($status_filter) . '">1</a></li>';
                        if ($start_page > 2) {
                            echo '<li class="page-item disabled"><span class="page-link">...</span></li>';
                        }
                    }
                    
                    // Show page range
                    for ($i = $start_page; $i <= $end_page; $i++): ?>
                        <li class="page-item <?php echo $i == $page ? 'active' : ''; ?>">
                            <a class="page-link" href="?page=<?php echo $i; ?>&search=<?php echo urlencode($search); ?>&status_filter=<?php echo urlencode($status_filter); ?>"><?php echo $i; ?></a>
                        </li>
                    <?php endfor;
                    
                    // Show last page if not in range
                    if ($end_page < $totalPages) {
                        if ($end_page < $totalPages - 1) {
                            echo '<li class="page-item disabled"><span class="page-link">...</span></li>';
                        }
                        echo '<li class="page-item"><a class="page-link" href="?page=' . $totalPages . '&search=' . urlencode($search) . '&status_filter=' . urlencode($status_filter) . '">' . $totalPages . '</a></li>';
                    }
                    ?>

                    <!-- Next Page -->
                    <?php if ($page < $totalPages): ?>
                        <li class="page-item">
                            <a class="page-link" href="?page=<?php echo ($page + 1); ?>&search=<?php echo urlencode($search); ?>&status_filter=<?php echo urlencode($status_filter); ?>">Next</a>
                        </li>
                    <?php else: ?>
                        <li class="page-item disabled">
                            <span class="page-link">Next</span>
                        </li>
                    <?php endif; ?>
                </ul>
                
                <!-- Page Info -->
                <div class="text-center mt-2">
                    <small class="text-muted">
                        Page <?php echo $page; ?> of <?php echo $totalPages; ?> 
                        (<?php echo $totalRecords; ?> total records)
                    </small>
                </div>
            </nav>
        <?php endif; ?>
    </div>

    <!-- Modal for Add/Edit Sales Activity -->
    <div class="modal fade" id="salesVisitModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="modalTitle">Add New Sales Activity</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form id="salesVisitForm" method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="action" id="formAction" value="create">
                        <input type="hidden" name="id" id="salesVisitId">
                        
                        <div class="mb-3">
                            <label for="id_pelanggan" class="form-label">ID Pelanggan *</label>
                            <input type="text" class="form-control" name="id_pelanggan" id="id_pelanggan" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="nama" class="form-label">Nama *</label>
                            <input type="text" class="form-control" name="nama" id="nama" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="alamat" class="form-label">Alamat *</label>
                            <textarea class="form-control" name="alamat" id="alamat" rows="3" required></textarea>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="hid" class="form-label">HID</label>
                                <input type="text" class="form-control" name="hid" id="hid">
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="no_hp" class="form-label">No HP *</label>
                                <input type="text" class="form-control" name="no_hp" id="no_hp" required>
                            </div>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="email" class="form-label">Email</label>
                                <input type="email" class="form-control" name="email" id="email">
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="paket" class="form-label">Paket *</label>
                                <select class="form-select" name="paket" id="paket" required>
                                    <option value="">Select Paket</option>
                                    <option value="10MB">10MB</option>
                                    <option value="50MB">50MB</option>
                                    <option value="100MB">100MB</option>
                                </select>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="titik_koordinat" class="form-label">Titik Koordinat</label>
                            <input type="text" class="form-control" name="titik_koordinat" id="titik_koordinat" placeholder="Latitude, Longitude">
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="tanggal_pemasangan" class="form-label">Tanggal Pemasangan</label>
                                <input type="date" class="form-control" name="tanggal_pemasangan" id="tanggal_pemasangan">
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="jatuh_tempo_pemasangan" class="form-label">Jatuh Tempo Pemasangan</label>
                                <input type="date" class="form-control" name="jatuh_tempo_pemasangan" id="jatuh_tempo_pemasangan">
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="status" class="form-label">Status *</label>
                            <select class="form-select" name="status" id="status" required>
                                <option value="Request">Request</option>
                                <option value="Cancel">Cancel</option>
                                <option value="Connected">Connected</option>
                                <option value="Disconnect">Disconnect</option>
                            </select>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        <button type="submit" class="btn btn-primary">Save</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="bg-light mt-5 py-3">
        <div class="container text-center">
            <p class="mb-0">&copy; <?php echo date('Y'); ?> All rights reserved.</p>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function resetForm() {
            document.getElementById('salesVisitForm').reset();
            document.getElementById('formAction').value = 'create';
            document.getElementById('modalTitle').textContent = 'Add New Sales Activity';
            document.getElementById('salesVisitId').value = '';
        }

        function editSalesVisit(id) {
            // Redirect to this page with edit parameter, preserve current page and filters
            const urlParams = new URLSearchParams(window.location.search);
            const currentPage = urlParams.get('page') || 1;
            const search = urlParams.get('search') || '';
            const statusFilter = urlParams.get('status_filter') || '';
            
            window.location.href = `sales_visit.php?edit=${id}&page=${currentPage}&search=${encodeURIComponent(search)}&status_filter=${encodeURIComponent(statusFilter)}`;
        }

        <?php if ($editData): ?>
        // Auto open modal if editing
        document.addEventListener('DOMContentLoaded', function() {
            const modal = new bootstrap.Modal(document.getElementById('salesVisitModal'));
            
            // Fill form with edit data
            document.getElementById('formAction').value = 'update';
            document.getElementById('modalTitle').textContent = 'Edit Sales Activity';
            document.getElementById('salesVisitId').value = '<?php echo $editData['id']; ?>';
            document.getElementById('id_pelanggan').value = '<?php echo htmlspecialchars($editData['id_pelanggan']); ?>';
            document.getElementById('nama').value = '<?php echo htmlspecialchars($editData['nama']); ?>';
            document.getElementById('alamat').value = '<?php echo htmlspecialchars($editData['alamat']); ?>';
            document.getElementById('hid').value = '<?php echo htmlspecialchars($editData['hid']); ?>';
            document.getElementById('no_hp').value = '<?php echo htmlspecialchars($editData['no_hp']); ?>';
            document.getElementById('email').value = '<?php echo htmlspecialchars($editData['email']); ?>';
            document.getElementById('paket').value = '<?php echo $editData['paket']; ?>';
            document.getElementById('titik_koordinat').value = '<?php echo htmlspecialchars($editData['titik_koordinat']); ?>';
            document.getElementById('tanggal_pemasangan').value = '<?php echo $editData['tanggal_pemasangan']; ?>';
            document.getElementById('jatuh_tempo_pemasangan').value = '<?php echo $editData['jatuh_tempo_pemasangan']; ?>';
            document.getElementById('status').value = '<?php echo $editData['status']; ?>';
            
            modal.show();
        });
        <?php endif; ?>

        function deleteSalesVisit(id) {
            if (confirm('Are you sure you want to delete this sales visit?')) {
                // Preserve current page and filters when deleting
                const urlParams = new URLSearchParams(window.location.search);
                const currentPage = urlParams.get('page') || 1;
                const search = urlParams.get('search') || '';
                const statusFilter = urlParams.get('status_filter') || '';
                
                const form = document.createElement('form');
                form.method = 'POST';
                form.innerHTML = `
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="id" value="${id}">
                    <input type="hidden" name="redirect_page" value="${currentPage}">
                    <input type="hidden" name="redirect_search" value="${search}">
                    <input type="hidden" name="redirect_status" value="${statusFilter}">
                `;
                document.body.appendChild(form);
                form.submit();
            }
        }

        // Check user permissions for actions
        function checkPermission(created_by, current_user_id, user_role) {
            return (user_role === 'admin') || (created_by == current_user_id);
        }

        // Add visual indicators for permission levels
        document.addEventListener('DOMContentLoaded', function() {
            const userRole = '<?php echo $user['role']; ?>';
            const currentUserId = <?php echo $_SESSION['user_id']; ?>;
            
            if (userRole === 'sales') {
                // METODE PALING AMAN - Gunakan setTimeout untuk memastikan DOM ready
                setTimeout(function() {
                    addSalesInfoBoxSafe();
                }, 100); // Delay 100ms untuk memastikan DOM fully loaded
            }
        });

        // Fungsi paling aman untuk menambah info box
        function addSalesInfoBoxSafe() {
            try {
                // Cek apakah sudah ada info box
                if (document.querySelector('.sales-info-box')) {
                    return; // Sudah ada, skip
                }
                
                const container = document.querySelector('.container');
                if (!container) {
                    console.log('Container not found');
                    return;
                }
                
                // Buat info box
                const infoBox = document.createElement('div');
                //infoBox.className = 'alert alert-info sales-info-box mb-3';
                infoBox.className = '';
                infoBox.innerHTML = ``;
                
                // METODE TERAMAN - Cari h1 dan insert setelahnya
                const h1 = container.querySelector('h1');
                if (h1) {
                    // Insert setelah h1 dengan cara yang aman
                    insertAfterElement(h1, infoBox);
                } else {
                    // Jika tidak ada h1, prepend ke container
                    container.insertBefore(infoBox, container.firstChild);
                }
                
                console.log('✅ Sales info box added successfully');
                
            } catch (error) {
                console.error('❌ Error adding sales info box:', error);
                // Fallback ultra-safe
                fallbackAddInfoBox();
            }
        }

        // Helper function untuk insert after element
        function insertAfterElement(referenceNode, newNode) {
            try {
                if (referenceNode.nextSibling) {
                    referenceNode.parentNode.insertBefore(newNode, referenceNode.nextSibling);
                } else {
                    referenceNode.parentNode.appendChild(newNode);
                }
            } catch (error) {
                console.error('Insert after failed:', error);
                // Fallback: append to parent
                referenceNode.parentNode.appendChild(newNode);
            }
        }

        // Fallback method jika semua gagal
        function fallbackAddInfoBox() {
            try {
                console.log('🔄 Using fallback method for info box');
                
                // Cari div pertama di container
                const container = document.querySelector('.container');
                const firstDiv = container.querySelector('div');
                
                if (firstDiv) {
                    // Buat info box dengan inline style
                    const infoHTML = ``;
                    
                    // Insert menggunakan insertAdjacentHTML (paling aman)
                    firstDiv.insertAdjacentHTML('beforebegin', infoHTML);
                    console.log('✅ Fallback method succeeded');
                }
                
            } catch (error) {
                console.error('❌ Even fallback failed:', error);
            }
        }

        // ATAU gunakan metode HTML injection yang sangat aman:
        function addInfoBoxViaHTML() {
            const userRole = '<?php echo $user['role']; ?>';
            
            if (userRole === 'sales') {
                // Cari tempat yang cocok dan inject HTML
                const targets = [
                    '.d-flex.justify-content-between.align-items-center.mb-4',
                    'h1',
                    '.container > div:first-child',
                    '.mb-4:first-of-type'
                ];
                
                for (let selector of targets) {
                    const target = document.querySelector(selector);
                    if (target) {
                        /*
                        target.insertAdjacentHTML('afterend', `
                            <div class="alert alert-info sales-info-box mb-3">
                                <i class="fas fa-info-circle me-2"></i>
                                <strong>Info:</strong> Sebagai Sales, Anda hanya dapat melihat dan mengedit data yang Anda input sendiri.
                            </div>
                        `);
                        */
                       target.insertAdjacentHTML('afterend', ``);
                        console.log(`✅ Info box added after ${selector}`);
                        break;
                    }
                }
            }
        }

        // Fungsi showDueToday untuk filter sales visit yang jatuh tempo hari ini
        function showDueToday() {
            try {
                // Get current URL
                const currentUrl = new URL(window.location.href);
                
                // Set filter parameters
                currentUrl.searchParams.set('due_filter', 'due_today');
                currentUrl.searchParams.set('page', '1'); // Reset ke halaman pertama
                
                // Keep existing search and status filter
                // (tidak perlu set lagi karena sudah ada di URL)
                
                // Redirect ke URL dengan filter due_today
                window.location.href = currentUrl.toString();
                
            } catch (error) {
                console.error('Error in showDueToday:', error);
                
                // Fallback method jika URL constructor gagal
                const baseUrl = window.location.pathname;
                const searchParams = new URLSearchParams(window.location.search);
                
                searchParams.set('due_filter', 'due_today');
                searchParams.set('page', '1');
                
                window.location.href = baseUrl + '?' + searchParams.toString();
            }
        }

            // Alternative function untuk show specific filter
            function showFilter(filterType) {
                try {
                    const url = new URL(window.location.href);
                    
                    switch(filterType) {
                        case 'due_today':
                            url.searchParams.set('due_filter', 'due_today');
                            break;
                        case 'overdue':
                            url.searchParams.set('due_filter', 'overdue');
                            break;
                        case 'due_week':
                            url.searchParams.set('due_filter', 'due_week');
                            break;
                        case 'all':
                            url.searchParams.delete('due_filter');
                            break;
                        default:
                            console.warn('Unknown filter type:', filterType);
                            return;
                    }
                    
                    url.searchParams.set('page', '1');
                    window.location.href = url.toString();
                    
                } catch (error) {
                    console.error('Error in showFilter:', error);
                }
            }

            // Quick access functions
            function showOverdue() {
                showFilter('overdue');
            }

            function showDueWeek() {
                showFilter('due_week');
            }

            function showAllDates() {
                showFilter('all');
            }

            function markAsRead(notificationId) {
                try {
                    // Kirim AJAX request
                    fetch('sales_visit.php', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: `action=mark_notification_read&notification_id=${notificationId}`
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            // 1. ACTUAL REMOVE UNREAD STYLING
                            const notificationItem = document.querySelector(`[data-notification-id="${notificationId}"]`);
                            if (notificationItem) {
                                notificationItem.classList.remove('unread');
                                
                                // Remove "New" badge
                                const badge = notificationItem.querySelector('.badge.bg-primary');
                                if (badge && badge.textContent.trim() === 'New') {
                                    badge.remove();
                                }
                            }
                            
                            // 2. ACTUAL UPDATE NOTIFICATION BADGE  
                            const notificationBadge = document.querySelector('.notification-badge');
                            if (notificationBadge) {
                                const currentCount = parseInt(notificationBadge.textContent) || 0;
                                const newCount = Math.max(0, currentCount - 1);
                                
                                if (newCount === 0) {
                                    notificationBadge.remove();
                                } else {
                                    notificationBadge.textContent = newCount;
                                }
                            }
                            
                            // 3. ACTUAL SHOW SUCCESS TOAST
                            if (typeof showToast === 'function') {
                                showToast('Notification marked as read', 'success');
                            }
                        }
                    })
                    .catch(error => {
                        // Error handling with fallback
                    });
                } catch (error) {
                    console.error('Error in markAsRead function:', error);
                }
            }

            function markAllAsRead() {
                try {
                    // 1. Check unread notifications
                    const unreadNotifications = document.querySelectorAll('.notification-item.unread');
                    
                    if (unreadNotifications.length === 0) {
                        showToast('No unread notifications found', 'info');
                        return;
                    }

                    // 2. Confirm action - BENAR: Execute jika user click OK
                    if (!confirm(`Mark all ${unreadNotifications.length} notifications as read?`)) {
                        // Jika user click CANCEL, keluar dari fungsi
                        return;
                    }

                    // 3. Show loading state
                    const markAllBtn = document.querySelector('button[onclick="markAllAsRead()"]');
                    const originalText = markAllBtn ? markAllBtn.innerHTML : '';
                    if (markAllBtn) {
                        markAllBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Marking...';
                        markAllBtn.disabled = true;
                    }

                    // 4. Send AJAX request - HANYA jika user confirm
                    fetch('sales_visit.php', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: 'action=mark_all_notifications_read'
                    })
                    .then(response => {
                        if (!response.ok) {
                            throw new Error('Network response was not ok');
                        }
                        return response.json();
                    })
                    .then(data => {
                        if (data.success) {
                            // 5. Update UI on success
                            unreadNotifications.forEach(item => {
                                item.classList.remove('unread');
                                
                                // Remove "New" badges
                                const badge = item.querySelector('.badge.bg-primary');
                                if (badge && badge.textContent === 'New') {
                                    badge.remove();
                                }
                            });
                            
                            // Remove notification badge completely
                            const notificationBadge = document.querySelector('.notification-badge');
                            if (notificationBadge) {
                                notificationBadge.remove();
                            }
                            
                            // Hide "Mark all read" button
                            const markAllHeaderBtn = document.querySelector('button[onclick="markAllAsRead()"]');
                            if (markAllHeaderBtn) {
                                markAllHeaderBtn.style.display = 'none';
                            }
                            
                            // 6. Show success message
                            showToast(`All ${unreadNotifications.length} notifications marked as read`, 'success');
                            
                            console.log('All notifications marked as read successfully');
                        } else {
                            throw new Error(data.error || 'Server returned success false');
                        }
                    })
                    .catch(error => {
                        console.error('Error marking all notifications as read:', error);
                        showToast('Error marking notifications as read', 'error');
                        
                        // Fallback: reload page to ensure consistency
                        setTimeout(() => {
                            location.reload();
                        }, 2000);
                    })
                    .finally(() => {
                        // Restore button state
                        if (markAllBtn) {
                            markAllBtn.innerHTML = originalText;
                            markAllBtn.disabled = false;
                        }
                    });
                    
                } catch (error) {
                    console.error('Error in markAllAsRead function:', error);
                    showToast('Error processing request', 'error');
                }
            }

            function showToast(message, type) {
            try {
                // Remove existing toast
                const existingToast = document.getElementById('dynamicToast');
                if (existingToast) existingToast.remove();
                
                // Create new toast with proper styling
                const toast = document.createElement('div');
                toast.id = 'dynamicToast';
                toast.className = `alert alert-${type === 'success' ? 'success' : type === 'error' ? 'danger' : 'info'} alert-dismissible fade show position-fixed`;
                
                // Proper positioning and styling
                toast.style.cssText = `
                    top: 20px; right: 20px; z-index: 9999;
                    min-width: 300px; max-width: 500px;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                    border-radius: 8px;
                `;
                
                // Icon dan content
                toast.innerHTML = `
                    <div class="d-flex align-items-center">
                        <i class="fas ${icon} me-2"></i>
                        <div class="flex-grow-1">${message}</div>
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                `;
                
                document.body.appendChild(toast);
                
                // Auto remove after 4 seconds
                setTimeout(() => {
                    if (toast && toast.parentNode) {
                        toast.remove();
                    }
                }, 4000);
                
            } catch (error) {
                // Fallback ke native alert
                alert(message);
            }
        }
    </script>
</body>
</html>

<?php
$conn->close();
?>