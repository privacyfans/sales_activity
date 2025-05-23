<?php
// Start session
session_start();
define('DB_HOST', '151.106.119.252');
define('DB_USER', 'cbnb9676_cbnbandung_user');
define('DB_PASS', 'Arkan@199003');
define('DB_NAME', 'cbnb9676_cbnbandung');

// Fungsi untuk mengecek apakah user sudah login dan memiliki akses admin
function checkAdminLogin() {
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
        
        // Check if user has admin role
        if ($user['role'] !== 'admin') {
            header("Location: index.php?error=access_denied");
            exit();
        }
        
        return $user;
        
    } catch(PDOException $e) {
        die("Error: " . $e->getMessage());
    }
}

$user = checkAdminLogin();
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

// Handle form submissions
$message = '';
$messageType = '';

// Check for redirect message
if (isset($_GET['message'])) {
    $message = $_GET['message'];
    $messageType = isset($_GET['type']) ? $_GET['type'] : 'info';
}

// Create/Update/Delete
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $action = $_POST['action'];
    
    if ($action == 'create' || $action == 'update') {
        $username_input = $_POST['username'];
        $password_input = $_POST['password'];
        $email = $_POST['email'];
        $full_name = $_POST['full_name'];
        $account_status = $_POST['account_status'];
        $role = $_POST['role'];
        
        if ($action == 'create') {
            // Check if username already exists
            $checkStmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
            $checkStmt->bind_param("s", $username_input);
            $checkStmt->execute();
            $checkResult = $checkStmt->get_result();
            
            if ($checkResult->num_rows > 0) {
                $message = "Username sudah ada! Pilih username lain.";
                $messageType = "danger";
            } else {
                // Hash password
                $hashed_password = password_hash($password_input, PASSWORD_DEFAULT);
                
                $sql = "INSERT INTO users (username, password, email, full_name, account_status, role, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())";
                $stmt = $conn->prepare($sql);
                $stmt->bind_param("ssssss", $username_input, $hashed_password, $email, $full_name, $account_status, $role);
                
                if ($stmt->execute()) {
                    $message = "User berhasil ditambahkan!";
                    $messageType = "success";
                } else {
                    $message = "Error: " . $conn->error;
                    $messageType = "danger";
                }
            }
        } else {
            $id = $_POST['id'];
            
            // Check if username already exists (exclude current user)
            $checkStmt = $conn->prepare("SELECT id FROM users WHERE username = ? AND id != ?");
            $checkStmt->bind_param("si", $username_input, $id);
            $checkStmt->execute();
            $checkResult = $checkStmt->get_result();
            
            if ($checkResult->num_rows > 0) {
                $message = "Username sudah ada! Pilih username lain.";
                $messageType = "danger";
            } else {
                if (!empty($password_input)) {
                    // Update with new password
                    $hashed_password = password_hash($password_input, PASSWORD_DEFAULT);
                    $sql = "UPDATE users SET username=?, password=?, email=?, full_name=?, account_status=?, role=?, updated_at=NOW() WHERE id=?";
                    $stmt = $conn->prepare($sql);
                    $stmt->bind_param("ssssssi", $username_input, $hashed_password, $email, $full_name, $account_status, $role, $id);
                } else {
                    // Update without changing password
                    $sql = "UPDATE users SET username=?, email=?, full_name=?, account_status=?, role=?, updated_at=NOW() WHERE id=?";
                    $stmt = $conn->prepare($sql);
                    $stmt->bind_param("sssssi", $username_input, $email, $full_name, $account_status, $role, $id);
                }
                
                if ($stmt->execute()) {
                    $message = "User berhasil diupdate!";
                    $messageType = "success";
                } else {
                    $message = "Error: " . $conn->error;
                    $messageType = "danger";
                }
            }
        }
    }
    
    // Delete
    if ($action == 'delete') {
        $id = $_POST['id'];
        
        // Prevent deleting own account
        if ($id == $_SESSION['user_id']) {
            $message = "Anda tidak dapat menghapus akun sendiri!";
            $messageType = "danger";
        } else {
            $sql = "DELETE FROM users WHERE id=?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("i", $id);
            
            if ($stmt->execute()) {
                $message = "User berhasil dihapus!";
                $messageType = "success";
                
                // Redirect back to the same page with filters preserved
                $redirectPage = isset($_POST['redirect_page']) ? $_POST['redirect_page'] : 1;
                $redirectSearch = isset($_POST['redirect_search']) ? $_POST['redirect_search'] : '';
                $redirectRole = isset($_POST['redirect_role']) ? $_POST['redirect_role'] : '';
                $redirectStatus = isset($_POST['redirect_status']) ? $_POST['redirect_status'] : '';
                
                $redirectUrl = "user_management.php?page=" . $redirectPage;
                if (!empty($redirectSearch)) {
                    $redirectUrl .= "&search=" . urlencode($redirectSearch);
                }
                if (!empty($redirectRole)) {
                    $redirectUrl .= "&role_filter=" . urlencode($redirectRole);
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
    }
}

// Search functionality
$search = isset($_GET['search']) ? $conn->real_escape_string($_GET['search']) : '';
$role_filter = isset($_GET['role_filter']) ? $_GET['role_filter'] : '';
$status_filter = isset($_GET['status_filter']) ? $_GET['status_filter'] : '';

// Pagination
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$records_per_page = 10;
$offset = ($page - 1) * $records_per_page;

// Build base query for counting
$countSql = "SELECT COUNT(*) as total FROM users WHERE 1=1";
$params = [];
$types = '';

if (!empty($search)) {
    $countSql .= " AND (username LIKE ? OR email LIKE ? OR full_name LIKE ?)";
    $searchParam = "%$search%";
    for ($i = 0; $i < 3; $i++) {
        $params[] = $searchParam;
        $types .= 's';
    }
}

if (!empty($role_filter)) {
    $countSql .= " AND role = ?";
    $params[] = $role_filter;
    $types .= 's';
}

if (!empty($status_filter)) {
    $countSql .= " AND account_status = ?";
    $params[] = $status_filter;
    $types .= 's';
}

// Get total records
$countStmt = $conn->prepare($countSql);
if (!empty($params)) {
    $countStmt->bind_param($types, ...$params);
}
$countStmt->execute();
$totalRecords = $countStmt->get_result()->fetch_assoc()['total'];
$totalPages = ceil($totalRecords / $records_per_page);

// Build main query with pagination
$sql = "SELECT * FROM users WHERE 1=1";
$params = []; // Reset params for main query
$types = '';

if (!empty($search)) {
    $sql .= " AND (username LIKE ? OR email LIKE ? OR full_name LIKE ?)";
    $searchParam = "%$search%";
    for ($i = 0; $i < 3; $i++) {
        $params[] = $searchParam;
        $types .= 's';
    }
}

if (!empty($role_filter)) {
    $sql .= " AND role = ?";
    $params[] = $role_filter;
    $types .= 's';
}

if (!empty($status_filter)) {
    $sql .= " AND account_status = ?";
    $params[] = $status_filter;
    $types .= 's';
}

$sql .= " ORDER BY created_at DESC LIMIT ? OFFSET ?";
$params[] = $records_per_page;
$params[] = $offset;
$types .= 'ii';

$stmt = $conn->prepare($sql);
if (!empty($params)) {
    $stmt->bind_param($types, ...$params);
}
$stmt->execute();
$result = $stmt->get_result();

// Get data for edit
$editData = null;
if (isset($_GET['edit'])) {
    $editId = $_GET['edit'];
    $editStmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
    $editStmt->bind_param("i", $editId);
    $editStmt->execute();
    $editData = $editStmt->get_result()->fetch_assoc();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management</title>
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
        .password-toggle {
            cursor: pointer;
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
                    <li class="nav-item">
                        <a class="nav-link active" href="user_management.php">User Management</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="change_password.php">Change Password</a>
                    </li>
                </ul>
                <div class="d-flex">
                    <span class="navbar-text me-3">
                        Welcome, <?php echo htmlspecialchars($user['full_name']); ?> (<?php echo ucfirst($user['role']); ?>)
                    </span>
                    <a href="logout.php" class="btn btn-outline-danger">Logout</a>
                </div>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <h1 class="text-center mb-4">User Management</h1>
        
        <?php if ($message): ?>
            <div class="alert alert-<?php echo $messageType; ?> alert-dismissible fade show" role="alert">
                <?php echo $message; ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <!-- Add New Button -->
        <div class="mb-4">
            <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#userModal" onclick="resetForm()">
                <i class="fas fa-plus"></i> Add New User
            </button>
        </div>

        <!-- Search and Filter -->
        <div class="row mb-4">
            <div class="col-md-8">
                <form method="GET" action="" class="d-flex">
                    <input type="hidden" name="page" value="1">
                    <input type="text" name="search" placeholder="Search username, email, full name..." value="<?php echo htmlspecialchars($search); ?>" class="form-control me-2">
                    <select name="role_filter" class="form-select me-2" style="width: auto;">
                        <option value="">All Roles</option>
                        <option value="admin" <?php echo $role_filter == 'admin' ? 'selected' : ''; ?>>Admin</option>
                        <option value="sales" <?php echo $role_filter == 'sales' ? 'selected' : ''; ?>>Sales</option>
                    </select>
                    <select name="status_filter" class="form-select me-2" style="width: auto;">
                        <option value="">All Status</option>
                        <option value="active" <?php echo $status_filter == 'active' ? 'selected' : ''; ?>>Active</option>
                        <option value="inactive" <?php echo $status_filter == 'inactive' ? 'selected' : ''; ?>>Inactive</option>
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
                        <th>Username</th>
                        <th>Full Name</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Last Login</th>
                        <th>Created At</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ($result->num_rows > 0): ?>
                        <?php while($row = $result->fetch_assoc()): ?>
                            <tr>
                                <td>
                                    <button class="btn btn-sm btn-warning me-1" onclick="editUser(<?php echo $row['id']; ?>)" 
                                            <?php echo $row['id'] == $_SESSION['user_id'] ? 'title="Your account"' : ''; ?>>
                                        <i class="fas fa-edit"></i>
                                    </button>
                                    <?php if ($row['id'] != $_SESSION['user_id']): ?>
                                        <button class="btn btn-sm btn-danger" onclick="deleteUser(<?php echo $row['id']; ?>)">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    <?php else: ?>
                                        <button class="btn btn-sm btn-secondary" disabled title="Cannot delete own account">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo htmlspecialchars($row['id']); ?></td>
                                <td><?php echo htmlspecialchars($row['username']); ?></td>
                                <td><?php echo htmlspecialchars($row['full_name']); ?></td>
                                <td><?php echo htmlspecialchars($row['email']); ?></td>
                                <td>
                                    <span class="badge bg-<?php echo $row['role'] == 'admin' ? 'danger' : 'info'; ?>">
                                        <?php echo ucfirst($row['role']); ?>
                                    </span>
                                </td>
                                <td>
                                    <span class="badge bg-<?php echo $row['account_status'] == 'active' ? 'success' : 'secondary'; ?>">
                                        <?php echo ucfirst($row['account_status']); ?>
                                    </span>
                                </td>
                                <td><?php echo $row['last_login'] ? date('d/m/Y H:i', strtotime($row['last_login'])) : 'Never'; ?></td>
                                <td><?php echo $row['created_at'] ? date('d/m/Y H:i', strtotime($row['created_at'])) : '-'; ?></td>
                            </tr>
                        <?php endwhile; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="9" class="text-center">No users found</td>
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
                            <a class="page-link" href="?page=<?php echo ($page - 1); ?>&search=<?php echo urlencode($search); ?>&role_filter=<?php echo urlencode($role_filter); ?>&status_filter=<?php echo urlencode($status_filter); ?>">Previous</a>
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
                    
                    if ($start_page > 1) {
                        echo '<li class="page-item"><a class="page-link" href="?page=1&search=' . urlencode($search) . '&role_filter=' . urlencode($role_filter) . '&status_filter=' . urlencode($status_filter) . '">1</a></li>';
                        if ($start_page > 2) {
                            echo '<li class="page-item disabled"><span class="page-link">...</span></li>';
                        }
                    }
                    
                    for ($i = $start_page; $i <= $end_page; $i++): ?>
                        <li class="page-item <?php echo $i == $page ? 'active' : ''; ?>">
                            <a class="page-link" href="?page=<?php echo $i; ?>&search=<?php echo urlencode($search); ?>&role_filter=<?php echo urlencode($role_filter); ?>&status_filter=<?php echo urlencode($status_filter); ?>"><?php echo $i; ?></a>
                        </li>
                    <?php endfor;
                    
                    if ($end_page < $totalPages) {
                        if ($end_page < $totalPages - 1) {
                            echo '<li class="page-item disabled"><span class="page-link">...</span></li>';
                        }
                        echo '<li class="page-item"><a class="page-link" href="?page=' . $totalPages . '&search=' . urlencode($search) . '&role_filter=' . urlencode($role_filter) . '&status_filter=' . urlencode($status_filter) . '">' . $totalPages . '</a></li>';
                    }
                    ?>

                    <!-- Next Page -->
                    <?php if ($page < $totalPages): ?>
                        <li class="page-item">
                            <a class="page-link" href="?page=<?php echo ($page + 1); ?>&search=<?php echo urlencode($search); ?>&role_filter=<?php echo urlencode($role_filter); ?>&status_filter=<?php echo urlencode($status_filter); ?>">Next</a>
                        </li>
                    <?php else: ?>
                        <li class="page-item disabled">
                            <span class="page-link">Next</span>
                        </li>
                    <?php endif; ?>
                </ul>
                
                <div class="text-center mt-2">
                    <small class="text-muted">
                        Page <?php echo $page; ?> of <?php echo $totalPages; ?> 
                        (<?php echo $totalRecords; ?> total users)
                    </small>
                </div>
            </nav>
        <?php endif; ?>
    </div>

    <!-- Modal for Add/Edit User -->
    <div class="modal fade" id="userModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="modalTitle">Add New User</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form id="userForm" method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="action" id="formAction" value="create">
                        <input type="hidden" name="id" id="userId">
                        
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="username" class="form-label">Username *</label>
                                <input type="text" class="form-control" name="username" id="username" required>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="full_name" class="form-label">Full Name *</label>
                                <input type="text" class="form-control" name="full_name" id="full_name" required>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="email" class="form-label">Email *</label>
                            <input type="email" class="form-control" name="email" id="email" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="password" class="form-label">Password <span id="passwordRequired">*</span></label>
                            <div class="input-group">
                                <input type="password" class="form-control" name="password" id="password">
                                <button type="button" class="btn btn-outline-secondary password-toggle" onclick="togglePassword()">
                                    <i class="fas fa-eye" id="passwordIcon"></i>
                                </button>
                            </div>
                            <small class="form-text text-muted" id="passwordHelp">Minimum 6 characters</small>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="role" class="form-label">Role *</label>
                                <select class="form-select" name="role" id="role" required>
                                    <option value="">Select Role</option>
                                    <option value="admin">Admin</option>
                                    <option value="sales">Sales</option>
                                </select>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="account_status" class="form-label">Account Status *</label>
                                <select class="form-select" name="account_status" id="account_status" required>
                                    <option value="">Select Status</option>
                                    <option value="active">Active</option>
                                    <option value="inactive">Inactive</option>
                                </select>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        <button type="submit" class="btn btn-primary">Save User</button>
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
            document.getElementById('userForm').reset();
            document.getElementById('formAction').value = 'create';
            document.getElementById('modalTitle').textContent = 'Add New User';
            document.getElementById('userId').value = '';
            document.getElementById('password').required = true;
            document.getElementById('passwordRequired').style.display = 'inline';
            document.getElementById('passwordHelp').textContent = 'Minimum 6 characters';
        }

        function editUser(id) {
            const urlParams = new URLSearchParams(window.location.search);
            const currentPage = urlParams.get('page') || 1;
            const search = urlParams.get('search') || '';
            const roleFilter = urlParams.get('role_filter') || '';
            const statusFilter = urlParams.get('status_filter') || '';
            
            window.location.href = `user_management.php?edit=${id}&page=${currentPage}&search=${encodeURIComponent(search)}&role_filter=${encodeURIComponent(roleFilter)}&status_filter=${encodeURIComponent(statusFilter)}`;
        }

        function deleteUser(id) {
            if (confirm('Are you sure you want to delete this user? This action cannot be undone.')) {
                const urlParams = new URLSearchParams(window.location.search);
                const currentPage = urlParams.get('page') || 1;
                const search = urlParams.get('search') || '';
                const roleFilter = urlParams.get('role_filter') || '';
                const statusFilter = urlParams.get('status_filter') || '';
                
                const form = document.createElement('form');
                form.method = 'POST';
                form.innerHTML = `
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="id" value="${id}">
                    <input type="hidden" name="redirect_page" value="${currentPage}">
                    <input type="hidden" name="redirect_search" value="${search}">
                    <input type="hidden" name="redirect_role" value="${roleFilter}">
                    <input type="hidden" name="redirect_status" value="${statusFilter}">
                `;
                document.body.appendChild(form);
                form.submit();
            }
        }

        function togglePassword() {
            const passwordInput = document.getElementById('password');
            const passwordIcon = document.getElementById('passwordIcon');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                passwordIcon.className = 'fas fa-eye-slash';
            } else {
                passwordInput.type = 'password';
                passwordIcon.className = 'fas fa-eye';
            }
        }

        // Form validation
        document.getElementById('userForm').addEventListener('submit', function(e) {
            const password = document.getElementById('password').value;
            const action = document.getElementById('formAction').value;
            
            if (action === 'create' && password.length < 6) {
                e.preventDefault();
                alert('Password must be at least 6 characters long');
                return false;
            }
            
            if (action === 'update' && password !== '' && password.length < 6) {
                e.preventDefault();
                alert('Password must be at least 6 characters long');
                return false;
            }
        });

        <?php if ($editData): ?>
        // Auto open modal if editing
        document.addEventListener('DOMContentLoaded', function() {
            const modal = new bootstrap.Modal(document.getElementById('userModal'));
            
            // Fill form with edit data
            document.getElementById('formAction').value = 'update';
            document.getElementById('modalTitle').textContent = 'Edit User';
            document.getElementById('userId').value = '<?php echo $editData['id']; ?>';
            document.getElementById('username').value = '<?php echo htmlspecialchars($editData['username']); ?>';
            document.getElementById('full_name').value = '<?php echo htmlspecialchars($editData['full_name']); ?>';
            document.getElementById('email').value = '<?php echo htmlspecialchars($editData['email']); ?>';
            document.getElementById('role').value = '<?php echo $editData['role']; ?>';
            document.getElementById('account_status').value = '<?php echo $editData['account_status']; ?>';
            
            // Make password optional for updates
            document.getElementById('password').required = false;
            document.getElementById('passwordRequired').style.display = 'none';
            document.getElementById('passwordHelp').textContent = 'Leave blank to keep current password';
            
            modal.show();
        });
        <?php endif; ?>
    </script>
</body>
</html>

<?php
$conn->close();
?>