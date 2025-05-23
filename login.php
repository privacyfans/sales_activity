<?php
// Configuration database
define('DB_HOST', '151.106.119.252');
define('DB_USER', 'cbnb9676_cbnbandung_user');
define('DB_PASS', 'Arkan@199003');
define('DB_NAME', 'cbnb9676_cbnbandung');

// Fungsi untuk membuat koneksi database yang aman
function createDBConnection() {
    try {
        $conn = new PDO(
            "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME,
            DB_USER,
            DB_PASS,
            array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION)
        );
        return $conn;
    } catch(PDOException $e) {
        die("Koneksi gagal: " . $e->getMessage());
    }
}

// Class untuk menangani login
class UserAuth {
    private $db;
    
    public function __construct() {
        $this->db = createDBConnection();
    }
    
    // Fungsi untuk membersihkan input
    private function sanitizeInput($data) {
        $data = trim($data);
        $data = stripslashes($data);
        $data = htmlspecialchars($data);
        return $data;
    }
    
    // Fungsi untuk memverifikasi login
    public function login($username, $password) {
        try {
            // Bersihkan input
            $username = $this->sanitizeInput($username);
            
            // Prepared statement untuk mencegah SQL injection - tambahkan role dan account_status
            $stmt = $this->db->prepare("SELECT id, username, full_name, password, role, account_status, failed_attempts, last_failed_attempt FROM users WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // Cek jika user ditemukan
            if ($user) {
                // Cek status akun
                if ($user['account_status'] !== 'active') {
                    return array('status' => false, 'message' => 'Akun tidak aktif. Hubungi administrator.');
                }
                
                // Cek jika akun terkunci
                if ($user['failed_attempts'] >= 3 && time() - strtotime($user['last_failed_attempt']) < 300) { // 5 menit lockout
                    $remaining_time = 300 - (time() - strtotime($user['last_failed_attempt']));
                    $minutes = floor($remaining_time / 60);
                    $seconds = $remaining_time % 60;
                    $seconds_formatted = sprintf("%02d", $seconds);
                    return array('status' => false, 'message' => "Akun terkunci. Coba lagi dalam {$minutes}:{$seconds_formatted}");
                }
               
                // Verifikasi password
                if (password_verify($password, $user['password'])) {
                    // Reset failed attempts jika login berhasil
                    $stmt = $this->db->prepare("UPDATE users SET failed_attempts = 0, last_failed_attempt = NULL, last_login = NOW() WHERE id = ?");
                    $stmt->execute([$user['id']]);
                    
                    // Mulai session
                    session_start();
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    $_SESSION['user_role'] = $user['role'];
                    $_SESSION['user_full_name'] = $user['full_name'];
                    $_SESSION['last_activity'] = time();
                    
                    // Generate token baru untuk keamanan session
                    $_SESSION['token'] = bin2hex(random_bytes(32));
                    
                    return array(
                        'status' => true, 
                        'message' => 'Login berhasil',
                        'role' => $user['role'],
                        'redirect' => $this->getRedirectUrl($user['role'])
                    );
                } else {
                    // Update failed attempts
                    $failed_attempts = $user['failed_attempts'] + 1;
                    $stmt = $this->db->prepare("UPDATE users SET failed_attempts = ?, last_failed_attempt = NOW() WHERE id = ?");
                    $stmt->execute([$failed_attempts, $user['id']]);
                    
                    $remaining_attempts = 3 - $failed_attempts;
                    if ($remaining_attempts > 0) {
                        return array('status' => false, 'message' => "Username atau password salah. Sisa percobaan: {$remaining_attempts}");
                    } else {
                        return array('status' => false, 'message' => 'Username atau password salah. Akun dikunci selama 5 menit.');
                    }
                }
            } else {
                return array('status' => false, 'message' => 'Username atau password salah');
            }
        } catch(PDOException $e) {
            error_log("Login error: " . $e->getMessage());
            return array('status' => false, 'message' => 'Terjadi kesalahan sistem');
        }
    }
    
    // Fungsi untuk menentukan redirect URL berdasarkan role
    private function getRedirectUrl($role) {
        switch($role) {
            case 'admin':
                return 'user_management.php';
            case 'sales':
                return 'sales_visit.php';
            default:
                return 'index.php';
        }
    }
    
    // Fungsi untuk logout
    public function logout() {
        session_start();
        $_SESSION = array();
        session_destroy();
        return array('status' => true, 'message' => 'Logout berhasil');
    }
}

// Handle logout
if (isset($_GET['action']) && $_GET['action'] == 'logout') {
    $auth = new UserAuth();
    $result = $auth->logout();
    header('Location: login.php?message=' . urlencode($result['message']));
    exit;
}

// Check if user is already logged in
session_start();
if (isset($_SESSION['user_id']) && isset($_SESSION['token'])) {
    // Verify session is still valid
    try {
        $conn = createDBConnection();
        $stmt = $conn->prepare("SELECT role FROM users WHERE id = ? AND account_status = 'active'");
        $stmt->execute([$_SESSION['user_id']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user) {
            // User is already logged in, redirect based on role
            $auth = new UserAuth();
            $redirectUrl = 'index.php';
            if (isset($user['role'])) {
                switch($user['role']) {
                    case 'admin':
                        $redirectUrl = 'user_management.php';
                        break;
                    case 'sales':
                        $redirectUrl = 'sales_visit.php';
                        break;
                }
            }
            header('Location: ' . $redirectUrl);
            exit;
        }
    } catch(PDOException $e) {
        // Session invalid, continue to login
        session_destroy();
    }
}

// Handle login form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $auth = new UserAuth();
    
    if (isset($_POST['username']) && isset($_POST['password'])) {
        $result = $auth->login($_POST['username'], $_POST['password']);
        
        if ($result['status']) {
            // Redirect berdasarkan role
            header('Location: ' . $result['redirect']);
            exit;
        } else {
            $error_message = $result['message'];
        }
    }
}

// Get message from URL parameter (for logout message, etc.)
$info_message = isset($_GET['message']) ? htmlspecialchars($_GET['message']) : '';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Sales Activity</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .login-container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            padding: 2.5rem;
            width: 100%;
            max-width: 420px;
            backdrop-filter: blur(10px);
        }
        .login-header {
            text-align: center;
            margin-bottom: 2rem;
        }
        .login-header h2 {
            color: #333;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        .login-header p {
            color: #666;
            font-size: 0.9rem;
        }
        .form-floating {
            margin-bottom: 1.5rem;
        }
        .form-control {
            border-radius: 10px;
            border: 2px solid #e1e5e9;
            padding: 0.75rem;
        }
        .form-control:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.25rem rgba(102, 126, 234, 0.15);
        }
        .btn-login {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 10px;
            padding: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            transition: all 0.3s ease;
        }
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.3);
        }
        .alert {
            border-radius: 10px;
            margin-bottom: 1.5rem;
        }
        .password-toggle {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: #666;
            cursor: pointer;
            z-index: 5;
        }
        .form-floating .password-toggle {
            top: 50%;
        }
        .role-info {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 1rem;
            margin-top: 1.5rem;
            font-size: 0.85rem;
            color: #666;
        }
    </style>
</head>
<body>

<div class="login-container">
    <div class="login-header">
        <i class="fas fa-book fa-3x text-primary mb-3"></i>
        <h2>Sales Activity</h2>
        <p>Silakan login untuk melanjutkan</p>
    </div>
    
    <?php if (isset($error_message)): ?>
        <div class="alert alert-danger d-flex align-items-center" role="alert">
            <i class="fas fa-exclamation-triangle me-2"></i>
            <?php echo $error_message; ?>
        </div>
    <?php endif; ?>
    
    <?php if ($info_message): ?>
        <div class="alert alert-info d-flex align-items-center" role="alert">
            <i class="fas fa-info-circle me-2"></i>
            <?php echo $info_message; ?>
        </div>
    <?php endif; ?>
    
    <form method="POST" action="" id="loginForm">
        <div class="form-floating">
            <input type="text" class="form-control" id="username" name="username" placeholder="Username" required autocomplete="username">
            <label for="username"><i class="fas fa-user me-2"></i>Username</label>
        </div>
        
        <div class="form-floating position-relative">
            <input type="password" class="form-control" id="password" name="password" placeholder="Password" required autocomplete="current-password">
            <label for="password"><i class="fas fa-lock me-2"></i>Password</label>
            <button type="button" class="password-toggle" onclick="togglePassword()">
                <i class="fas fa-eye" id="passwordIcon"></i>
            </button>
        </div>
        
        <div class="d-grid">
            <button type="submit" class="btn btn-primary btn-login">
                <i class="fas fa-sign-in-alt me-2"></i>Login
            </button>
        </div>
    </form>
    
    
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
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

// Auto-dismiss alerts after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = new bootstrap.Alert(alert);
            if (bsAlert) {
                bsAlert.close();
            }
        }, 5000);
    });
});

// Form validation
document.getElementById('loginForm').addEventListener('submit', function(e) {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    
    if (username.length < 3) {
        e.preventDefault();
        alert('Username harus minimal 3 karakter');
        return false;
    }
    
    if (password.length < 6) {
        e.preventDefault();
        alert('Password harus minimal 6 karakter');
        return false;
    }
});

// Check for session timeout message
const urlParams = new URLSearchParams(window.location.search);
if (urlParams.get('message') === 'timeout') {
    // Show timeout notification
    setTimeout(function() {
        if (!document.querySelector('.alert')) {
            const alertDiv = document.createElement('div');
            alertDiv.className = 'alert alert-warning alert-dismissible fade show';
            alertDiv.innerHTML = `
                <i class="fas fa-clock me-2"></i>
                Sesi Anda telah berakhir. Silakan login kembali.
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            document.querySelector('.login-container').insertBefore(alertDiv, document.querySelector('form'));
        }
    }, 100);
}
</script>
</body>
</html>