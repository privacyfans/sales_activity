<?php
// Start session
session_start();
define('DB_HOST', '151.106.119.252');
define('DB_USER', 'cbnb9676_cbnbandung_user');
define('DB_PASS', 'Arkan@199003');
define('DB_NAME', 'cbnb9676_cbnbandung');

require_once 'notification_manager.php';

// Fungsi untuk mengecek apakah user sudah login
function checkLogin() {
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
        
        return $user;
        
    } catch(PDOException $e) {
        die("Error: " . $e->getMessage());
    }
}

$user = checkLogin();

// Database connection
$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$notificationManager = new NotificationManager($conn);

// Handle actions
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if ($_POST['action'] == 'mark_read') {
        $notificationId = $_POST['notification_id'];
        $notificationManager->markAsRead($notificationId, $_SESSION['user_id']);
        header("Location: notifications.php?message=Notification marked as read");
        exit();
    }
    
    if ($_POST['action'] == 'mark_all_read') {
        $sql = "UPDATE notifications SET is_read = 1, read_at = NOW() WHERE user_id = ? AND is_read = 0";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $_SESSION['user_id']);
        $stmt->execute();
        header("Location: notifications.php?message=All notifications marked as read");
        exit();
    }
    
    if ($_POST['action'] == 'delete') {
        $notificationId = $_POST['notification_id'];
        $sql = "DELETE FROM notifications WHERE id = ? AND user_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ii", $notificationId, $_SESSION['user_id']);
        $stmt->execute();
        header("Location: notifications.php?message=Notification deleted");
        exit();
    }
}

// Pagination
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$records_per_page = 20;
$offset = ($page - 1) * $records_per_page;

// Filter
$filter = isset($_GET['filter']) ? $_GET['filter'] : 'all';

// Build query
$sql = "SELECT n.*, sv.nama as customer_name, sv.id_pelanggan, sv.status as visit_status
        FROM notifications n
        LEFT JOIN sales_visit sv ON n.sales_visit_id = sv.id
        WHERE n.user_id = ?";

$params = [$_SESSION['user_id']];
$types = 'i';

if ($filter == 'unread') {
    $sql .= " AND n.is_read = 0";
} elseif ($filter == 'due_today') {
    $sql .= " AND n.type = 'due_today'";
} elseif ($filter == 'overdue') {
    $sql .= " AND n.type = 'overdue'";
}

// Count total records
$countSql = str_replace("SELECT n.*, sv.nama as customer_name, sv.id_pelanggan, sv.status as visit_status", "SELECT COUNT(*) as total", $sql);
$countStmt = $conn->prepare($countSql);
$countStmt->bind_param($types, ...$params);
$countStmt->execute();
$totalRecords = $countStmt->get_result()->fetch_assoc()['total'];
$totalPages = ceil($totalRecords / $records_per_page);

// Get notifications
$sql .= " ORDER BY n.created_at DESC LIMIT ? OFFSET ?";
$params[] = $records_per_page;
$params[] = $offset;
$types .= 'ii';

$stmt = $conn->prepare($sql);
$stmt->bind_param($types, ...$params);
$stmt->execute();
$notifications = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

// Get unread count
$unreadCount = $notificationManager->getUnreadCount($_SESSION['user_id']);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Notifications - Sales Visit</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .nav-link { color: #333; }
        .nav-link:hover { color: #666; }
        .notification-card {
            transition: all 0.3s ease;
            border-left: 4px solid transparent;
        }
        .notification-card.unread {
            background-color: #f8f9fa;
            border-left-color: #007bff;
        }
        .notification-card:hover {
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            transform: translateY(-2px);
        }
        .notification-actions {
            opacity: 0;
            transition: opacity 0.3s ease;
        }
        .notification-card:hover .notification-actions {
            opacity: 1;
        }
        .filter-tabs .nav-link {
            color: #6c757d;
            border: none;
            background: none;
        }
        .filter-tabs .nav-link.active {
            color: #007bff;
            background-color: #e3f2fd;
            border-radius: 20px;
        }
        .notification-icon {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 15px;
        }
        .notification-icon.due-today {
            background-color: #fff3cd;
            color: #856404;
        }
        .notification-icon.overdue {
            background-color: #f8d7da;
            color: #721c24;
        }
        .notification-icon.reminder {
            background-color: #d4edda;
            color: #155724;
        }
    </style>
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
                        <a class="nav-link" href="sales_visit.php">Sales Visit</a>
                    </li>
                    <?php if ($user['role'] === 'admin'): ?>
                    <li class="nav-item">
                        <a class="nav-link" href="user_management.php">User Management</a>
                    </li>
                    <?php endif; ?>
                    <li class="nav-item">
                        <a class="nav-link active" href="notifications.php">Notifications</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="change_password.php">Change Password</a>
                    </li>
                </ul>
                <div class="d-flex">
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
            <h1>
                <i class="fas fa-bell me-2"></i>Notifications
                <?php if ($unreadCount > 0): ?>
                    <span class="badge bg-danger"><?php echo $unreadCount; ?></span>
                <?php endif; ?>
            </h1>
            <div>
                <a href="sales_visit.php" class="btn btn-outline-secondary me-2">
                    <i class="fas fa-arrow-left me-1"></i>Back to Sales Visit
                </a>
                <?php if ($unreadCount > 0): ?>
                    <form method="POST" class="d-inline">
                        <input type="hidden" name="action" value="mark_all_read">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-check-double me-1"></i>Mark All Read
                        </button>
                    </form>
                <?php endif; ?>
            </div>
        </div>

        <?php if (isset($_GET['message'])): ?>
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <?php echo htmlspecialchars($_GET['message']); ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <!-- Filter Tabs -->
        <ul class="nav nav-pills filter-tabs mb-4">
            <li class="nav-item">
                <a class="nav-link <?php echo $filter == 'all' ? 'active' : ''; ?>" href="?filter=all">
                    <i class="fas fa-list me-1"></i>All (<?php echo $totalRecords; ?>)
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link <?php echo $filter == 'unread' ? 'active' : ''; ?>" href="?filter=unread">
                    <i class="fas fa-envelope me-1"></i>Unread (<?php echo $unreadCount; ?>)
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link <?php echo $filter == 'due_today' ? 'active' : ''; ?>" href="?filter=due_today">
                    <i class="fas fa-clock me-1"></i>Due Today
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link <?php echo $filter == 'overdue' ? 'active' : ''; ?>" href="?filter=overdue">
                    <i class="fas fa-exclamation-triangle me-1"></i>Overdue
                </a>
            </li>
        </ul>

        <!-- Notifications List -->
        <?php if (empty($notifications)): ?>
            <div class="text-center py-5">
                <i class="fas fa-inbox fa-3x text-muted mb-3"></i>
                <h3 class="text-muted">No Notifications</h3>
                <p class="text-muted">You don't have any notifications yet.</p>
                <a href="sales_visit.php" class="btn btn-primary">
                    <i class="fas fa-plus me-1"></i>Add Sales Visit
                </a>
            </div>
        <?php else: ?>
            <div class="row">
                <?php foreach ($notifications as $notification): ?>
                    <div class="col-12 mb-3">
                        <div class="card notification-card <?php echo !$notification['is_read'] ? 'unread' : ''; ?>">
                            <div class="card-body">
                                <div class="d-flex align-items-start">
                                    <div class="notification-icon <?php echo $notification['type']; ?>">
                                        <?php
                                        $icon = 'fa-bell';
                                        switch($notification['type']) {
                                            case 'due_today':
                                                $icon = 'fa-clock';
                                                break;
                                            case 'overdue':
                                                $icon = 'fa-exclamation-triangle';
                                                break;
                                            case 'reminder':
                                                $icon = 'fa-calendar-alt';
                                                break;
                                        }
                                        ?>
                                        <i class="fas <?php echo $icon; ?>"></i>
                                    </div>
                                    
                                    <div class="flex-grow-1">
                                        <div class="d-flex justify-content-between align-items-start mb-2">
                                            <h5 class="card-title mb-0">
                                                <?php echo htmlspecialchars($notification['title']); ?>
                                                <?php if (!$notification['is_read']): ?>
                                                    <span class="badge bg-primary ms-2">New</span>
                                                <?php endif; ?>
                                            </h5>
                                            <small class="text-muted">
                                                <?php echo date('d/m/Y H:i', strtotime($notification['created_at'])); ?>
                                            </small>
                                        </div>
                                        
                                        <p class="card-text"><?php echo htmlspecialchars($notification['message']); ?></p>
                                        
                                        <?php if ($notification['customer_name']): ?>
                                            <div class="d-flex align-items-center mb-2">
                                                <span class="badge bg-secondary me-2">Customer:</span>
                                                <strong><?php echo htmlspecialchars($notification['customer_name']); ?></strong>
                                                <span class="ms-2 text-muted">(ID: <?php echo htmlspecialchars($notification['id_pelanggan']); ?>)</span>
                                                <?php if ($notification['visit_status']): ?>
                                                    <span class="badge bg-info ms-2"><?php echo $notification['visit_status']; ?></span>
                                                <?php endif; ?>
                                            </div>
                                        <?php endif; ?>
                                        
                                        <div class="notification-actions mt-3">
                                            <?php if (!$notification['is_read']): ?>
                                                <form method="POST" class="d-inline">
                                                    <input type="hidden" name="action" value="mark_read">
                                                    <input type="hidden" name="notification_id" value="<?php echo $notification['id']; ?>">
                                                    <button type="submit" class="btn btn-sm btn-outline-primary me-2">
                                                        <i class="fas fa-check me-1"></i>Mark as Read
                                                    </button>
                                                </form>
                                            <?php endif; ?>
                                            
                                            <?php if ($notification['sales_visit_id']): ?>
                                                <a href="sales_visit.php?edit=<?php echo $notification['sales_visit_id']; ?>" class="btn btn-sm btn-outline-info me-2">
                                                    <i class="fas fa-eye me-1"></i>View Details
                                                </a>
                                            <?php endif; ?>
                                            
                                            <form method="POST" class="d-inline">
                                                <input type="hidden" name="action" value="delete">
                                                <input type="hidden" name="notification_id" value="<?php echo $notification['id']; ?>">
                                                <button type="submit" class="btn btn-sm btn-outline-danger" onclick="return confirm('Delete this notification?')">
                                                    <i class="fas fa-trash me-1"></i>Delete
                                                </button>
                                            </form>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>

            <!-- Pagination -->
            <?php if ($totalPages > 1): ?>
                <nav aria-label="Notifications pagination" class="mt-4">
                    <ul class="pagination justify-content-center">
                        <?php if ($page > 1): ?>
                            <li class="page-item">
                                <a class="page-link" href="?page=<?php echo ($page - 1); ?>&filter=<?php echo $filter; ?>">Previous</a>
                            </li>
                        <?php endif; ?>

                        <?php
                        $start_page = max(1, $page - 2);
                        $end_page = min($totalPages, $page + 2);
                        
                        for ($i = $start_page; $i <= $end_page; $i++): ?>
                            <li class="page-item <?php echo $i == $page ? 'active' : ''; ?>">
                                <a class="page-link" href="?page=<?php echo $i; ?>&filter=<?php echo $filter; ?>"><?php echo $i; ?></a>
                            </li>
                        <?php endfor; ?>

                        <?php if ($page < $totalPages): ?>
                            <li class="page-item">
                                <a class="page-link" href="?page=<?php echo ($page + 1); ?>&filter=<?php echo $filter; ?>">Next</a>
                            </li>
                        <?php endif; ?>
                    </ul>
                    
                    <div class="text-center mt-2">
                        <small class="text-muted">
                            Page <?php echo $page; ?> of <?php echo $totalPages; ?> 
                            (<?php echo $totalRecords; ?> total notifications)
                        </small>
                    </div>
                </nav>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <!-- Footer -->
    <footer class="bg-light mt-5 py-3">
        <div class="container text-center">
            <p class="mb-0">&copy; <?php echo date('Y'); ?> All rights reserved.</p>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Auto-refresh notifications every 2 minutes
        setInterval(() => {
            if (window.location.href.includes('notifications.php')) {
                // Check for new notifications
                fetch('check_notifications.php?key=your_secret_cron_key')
                    .then(response => response.json())
                    .then(data => {
                        if (data.success && data.hasNewNotifications) {
                            // Show subtle notification that new notifications are available
                            showNewNotificationAlert();
                        }
                    })
                    .catch(error => {
                        console.log('Auto-check failed:', error);
                    });
            }
        }, 120000); // 2 minutes

        function showNewNotificationAlert() {
            // Create a subtle alert for new notifications
            if (!document.getElementById('newNotificationAlert')) {
                const alert = document.createElement('div');
                alert.id = 'newNotificationAlert';
                alert.className = 'alert alert-info alert-dismissible fade show position-fixed';
                alert.style.top = '20px';
                alert.style.right = '20px';
                alert.style.zIndex = '9999';
                alert.style.minWidth = '300px';
                alert.innerHTML = `
                    <i class="fas fa-bell me-2"></i>
                    <strong>New notifications available!</strong>
                    <button type="button" class="btn btn-sm btn-link p-0 ms-2" onclick="location.reload()">Refresh</button>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                `;
                document.body.appendChild(alert);
                
                // Auto-remove after 10 seconds
                setTimeout(() => {
                    if (alert.parentNode) {
                        alert.parentNode.removeChild(alert);
                    }
                }, 10000);
            }
        }

        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            // Ctrl/Cmd + A: Mark all as read
            if ((e.ctrlKey || e.metaKey) && e.key === 'a' && e.target.tagName !== 'INPUT') {
                e.preventDefault();
                const markAllForm = document.querySelector('form[method="POST"] input[value="mark_all_read"]');
                if (markAllForm) {
                    markAllForm.closest('form').submit();
                }
            }
            
            // R: Refresh page
            if (e.key === 'r' && !e.ctrlKey && !e.metaKey && e.target.tagName !== 'INPUT') {
                e.preventDefault();
                location.reload();
            }
        });
    </script>
</body>
</html>

<?php
$conn->close();
?>