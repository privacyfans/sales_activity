<?php
// File: auth_functions.php
// Fungsi-fungsi untuk authentication dan role checking

function checkUserRole($required_role = null) {
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
        
        $stmt = $conn->prepare("SELECT id, username, full_name, account_status, role FROM users WHERE id = ? AND account_status = 'active'");
        $stmt->execute([$_SESSION['user_id']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$user) {
            session_destroy();
            header("Location: login.php");
            exit();
        }
        
        // Check specific role if required
        if ($required_role && $user['role'] !== $required_role) {
            header("Location: index.php?error=access_denied&message=" . urlencode("Access denied. " . ucfirst($required_role) . " role required."));
            exit();
        }
        
        // Check for multiple roles
        if (is_array($required_role) && !in_array($user['role'], $required_role)) {
            header("Location: index.php?error=access_denied&message=" . urlencode("Access denied. Insufficient privileges."));
            exit();
        }
        
        return $user;
        
    } catch(PDOException $e) {
        die("Error: " . $e->getMessage());
    }
}

function hasRole($role) {
    if (!isset($_SESSION['user_role'])) {
        return false;
    }
    
    if (is_array($role)) {
        return in_array($_SESSION['user_role'], $role);
    }
    
    return $_SESSION['user_role'] === $role;
}

function isAdmin() {
    return hasRole('admin');
}

function isSales() {
    return hasRole('sales');
}

function canAccessUserManagement() {
    return isAdmin();
}

function canAccessSalesVisit() {
    return hasRole(['admin', 'sales']);
}

function canEditUser($user_id) {
    if (isAdmin()) {
        return true;
    }
    
    // Users can only edit their own profile
    return $_SESSION['user_id'] == $user_id;
}

function canDeleteUser($user_id) {
    if (!isAdmin()) {
        return false;
    }
    
    // Admin cannot delete their own account
    return $_SESSION['user_id'] != $user_id;
}

// Set user role in session (call this after successful login)
function setUserRoleInSession($user_data) {
    $_SESSION['user_role'] = $user_data['role'];
    $_SESSION['user_full_name'] = $user_data['full_name'];
}
?>