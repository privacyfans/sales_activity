<?php
// Start session
session_start();
define('DB_HOST', '151.106.119.252');
define('DB_USER', 'cbnb9676_cbnbandung_user');
define('DB_PASS', 'Arkan@199003');
define('DB_NAME', 'cbnb9676_cbnbandung');
// Fungsi untuk mengecek apakah user sudah login


function checkLogin() {
    // Cek apakah session user_id ada dan token ada
    if (!isset($_SESSION['user_id']) || !isset($_SESSION['token'])) {
        header("Location: login.php");
        exit();
    }
    
    // Koneksi ke database untuk verifikasi tambahan
    try {
       
        $conn = new PDO(
            "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME,
            DB_USER,
            DB_PASS,
            array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION)
        );
        // Verifikasi user masih aktif di database
        $stmt = $conn->prepare("SELECT username, full_name, account_status FROM users WHERE id = ? AND account_status = 'active'");
        $stmt->execute([$_SESSION['user_id']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$user) {
            // Jika user tidak ditemukan atau tidak aktif, logout
            session_destroy();
            header("Location: login.php");
            exit();
        }
        
        return $user;
        
    } catch(PDOException $e) {
        die("Error: " . $e->getMessage());
    }
}

// Cek login dan dapatkan data user
$user = checkLogin();

// Update last activity time
$_SESSION['last_activity'] = time();

// Cek timeout setelah 30 menit tidak ada aktivitas
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > 1800)) {
    session_destroy();
    header("Location: login.php?message=timeout");
    exit();
}



?>
<?php
// Database connection details

$servername = "151.106.119.252";
$username = "cbnb9676_cbnbandung_user";
$password = "Arkan@199003";
$dbname = "cbnb9676_cbnbandung";


// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);
// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Get all column names
$columnsQuery = "SHOW COLUMNS FROM hid_dedicated";
$columnsResult = $conn->query($columnsQuery);
$columns = [];
while ($row = $columnsResult->fetch_assoc()) {
    $columns[] = $row['Field'];
}

$search = isset($_GET['search']) ? $conn->real_escape_string($_GET['search']) : '';
$advancedSearch = isset($_GET['advanced_search']) ? $_GET['advanced_search'] : [];
$showResults = isset($_GET['search']) || !empty($advancedSearch);

if ($showResults) {
    $conditions = [];
    $params = [];
    $types = '';

    if (!empty($search)) {
        $searchConditions = [];
        foreach ($columns as $column) {
            $searchConditions[] = "$column LIKE ?";
            $params[] = "%$search%";
            $types .= 's';
        }
        $conditions[] = '(' . implode(' OR ', $searchConditions) . ')';
    }

    foreach ($advancedSearch as $column => $value) {
        if ($value !== '') {
            $conditions[] = "$column LIKE ?";
            $params[] = "%$value%";
            $types .= 's';
        }
    }

    $sql = "SELECT * FROM hid_dedicated";
    if (!empty($conditions)) {
        $sql .= " WHERE " . implode(' AND ', $conditions);
    }

    $stmt = $conn->prepare($sql);
    if (!empty($params)) {
        $stmt->bind_param($types, ...$params);
    }
    $stmt->execute();
    $result = $stmt->get_result();
     $numRows = $result->num_rows;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Search Dedicated HID</title>
    <!-- <script src="https://cdn.tailwindcss.com"></script> -->
    <link rel="icon" href="/search/favicon.ico" sizes="32x32">
    <link rel="shortcut icon" href="/search/favicon.ico">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .nav-link { color: #333; }
        .nav-link:hover { color: #666; }
        .welcome-section { background-color: #f8f9fa; }
    </style>
</head>

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
                        <a class="nav-link" href="change_password.php">Change Password</a>
                    </li>
            </ul>
            <div class="d-flex">
                <span class="navbar-text me-3">
                    Welcome, <?php echo htmlspecialchars($user['full_name']); ?>
                </span>
                <a href="logout.php" class="btn btn-outline-danger">Logout</a>
            </div>
        </div>
    </div>
</nav>

<body class="bg-light p-4">
    <div class="container">
        <h1 class="h3 font-weight-bold mb-4">Search Dedicated HID</h1>
        
        <!-- Quick Search Form -->
        <form action="" method="GET" class="mb-4 d-flex align-items-center">
            <input type="text" id="searchInput" name="search" value="<?php echo htmlspecialchars($search); ?>" placeholder="Quick Search..." class="form-control me-2" />
            <button type="submit" class="btn btn-primary me-2">Search</button>
            <button type="button" onclick="clearSearch()" class="btn btn-secondary">Clear</button>
        </form>

        <!-- Advanced Search Toggle Button -->
        <button id="toggleAdvancedSearch" class="btn btn-purple mb-4">
            Show Advanced Search
        </button>

        <!-- Advanced Search Form -->
        <form id="advancedSearchForm" action="" method="GET" class="mb-4 bg-white p-4 rounded shadow d-none">
            <h2 class="h5 font-weight-semibold mb-3">Advanced Search</h2>
            <div class="row g-3">
                <?php foreach ($columns as $column): ?>
                    <div class="col-md-4">
                        <label for="<?php echo $column; ?>" class="form-label"><?php echo ucfirst($column); ?></label>
                        <input type="text" id="<?php echo $column; ?>" name="advanced_search[<?php echo $column; ?>]" value="<?php echo isset($advancedSearch[$column]) ? htmlspecialchars($advancedSearch[$column]) : ''; ?>" class="form-control" />
                    </div>
                <?php endforeach; ?>
            </div>
            <div class="mt-3 d-flex justify-content-end">
                <button type="submit" class="btn btn-success me-2">Advanced Search</button>
                <button type="button" onclick="clearAdvancedSearch()" class="btn btn-secondary">Clear</button>
            </div>
        </form>

        <!-- Results Table -->
        <?php if ($showResults): ?>
            <?php if ($result->num_rows > 0): ?>
             <p class="mb-3">Number of Rows: <?php echo $numRows; ?></p>
                <div class="table-responsive">
                    <table class="table table-bordered">
                        <thead class="table-light">
                            <tr>
                                <th>Action</th>
                                <?php foreach ($columns as $column): ?>
                                    <th><?php echo htmlspecialchars($column); ?></th>
                                <?php endforeach; ?>
                            </tr>
                        </thead>
                        <tbody>
                            <?php while($row = $result->fetch_assoc()): ?>
                                <tr>
                                    <td>
                                        <button onclick="copyRowData(this)" class="btn btn-success">Copy</button>
                                    </td>
                                    <?php foreach ($columns as $column): ?>
                                        <td><?php echo htmlspecialchars($row[$column]); ?></td>
                                    <?php endforeach; ?>
                                </tr>
                            <?php endwhile; ?>
                        </tbody>
                    </table>
                </div>
            <?php else: ?>
                <p class="text-muted">No results found.</p>
            <?php endif; ?>
        <?php endif; ?>
    </div>
</body>

<footer class="bg-light mt-5 py-3">
    <div class="container text-center">
        <p class="mb-0">&copy; <?php echo date('Y'); ?> All rights reserved.</p>
    </div>
</footer>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/js/bootstrap.bundle.min.js"></script>

<script>
function copyRowData(button) {
    const row = button.closest('tr');
    const cells = row.querySelectorAll('td:not(:last-child)');
    let rowData = '';

    cells.forEach((cell, index) => {
        rowData += cell.textContent;
        if (index < cells.length - 1) {
            rowData += '\t';
        }
    });

    navigator.clipboard.writeText(rowData).then(() => {
        const originalText = button.textContent;
        button.textContent = 'Copied!';
        setTimeout(() => button.textContent = originalText, 2000);
    });
}

function clearSearch() {
    document.getElementById('searchInput').value = '';
    window.location.href = window.location.pathname;
}

function clearAdvancedSearch() {
    const inputs = document.querySelectorAll('input[name^="advanced_search"]');
    inputs.forEach(input => input.value = '');
}

// Toggle Advanced Search
document.getElementById('toggleAdvancedSearch').addEventListener('click', function () {
    const advancedSearchForm = document.getElementById('advancedSearchForm');
    advancedSearchForm.classList.toggle('d-none');
    this.textContent = advancedSearchForm.classList.contains('d-none') ? 'Show Advanced Search' : 'Hide Advanced Search';
});
</script>
