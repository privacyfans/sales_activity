<?php
// Start session
session_start();
define('DB_HOST', '151.106.119.252');
define('DB_USER', 'cbnb9676_cbnbandung_user');
define('DB_PASS', 'Arkan@199003');
define('DB_NAME', 'cbnb9676_cbnbandung');
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
        
        // Set role in session if not set
        if (!isset($_SESSION['user_role'])) {
            $_SESSION['user_role'] = $user['role'];
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
$columnsQuery = "SHOW COLUMNS FROM hid_new";
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

    $sql = "SELECT * FROM hid_new";
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
    <title>Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .nav-link { color: #333; }
        .nav-link:hover { color: #666; }
        .welcome-section { background-color: #f8f9fa; }
    </style>

<style>
        .sticky-row {
            position: sticky;
            top: 0;
            background-color: white;
            z-index: 1;
        }
        .flex-center {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 10vh;
        }
        .search-input {
            border: 1px solid #ccc;
        }
        @media (max-width: 640px) {
            .form-container {
                max-width: 90%;
            }
            .form-container input[type="text"],
            .form-container button {
                display: block;
                width: 100%;
                margin-top: 10px;
            }
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
                        <a class="nav-link" href="change_password.php">Change Password</a>
                    </li>
                    
                    <!-- Add more menu items as needed -->
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

   
        <div class="container mt-4">
        <h1 class="text-center mb-4">Search HID</h1>
        
        <!-- Quick Search Form -->
        <div class="flex-center mb-4">
            <div class="form-container">
                <form method="GET" action="" class="d-flex">
                    <input type="text" name="search" placeholder="Quick Search" value="<?php echo htmlspecialchars($search); ?>" class="form-control me-2">
                    <button type="submit" class="btn btn-primary">Search</button>
                </form>
            </div>
        </div>

        <!-- Advanced Search Toggle Button -->
        <div class="text-center mb-4">
            <button id="toggleAdvancedSearch" class="btn btn-secondary">
                Show Advanced Search
            </button>
        </div>

        <!-- Advanced Search Form -->
        <div id="advancedSearchForm" class="card p-4 mb-4" style="display: none;">
            <h2 class="card-title mb-4">Advanced Search</h2>
            <form action="" method="GET">
                <div class="row">
                    <?php foreach ($columns as $column): ?>
                        <div class="col-md-4 mb-3">
                            <label for="<?php echo $column; ?>" class="form-label"><?php echo ucfirst($column); ?></label>
                            <input type="text" id="<?php echo $column; ?>" name="advanced_search[<?php echo $column; ?>]" value="<?php echo isset($advancedSearch[$column]) ? htmlspecialchars($advancedSearch[$column]) : ''; ?>" class="form-control">
                        </div>
                    <?php endforeach; ?>
                </div>
                <div class="text-end">
                    <button type="submit" class="btn btn-success">Advanced Search</button>
                    <button type="button" onclick="clearAdvancedSearch()" class="btn btn-outline-secondary">Clear</button>
                </div>
            </form>
        </div>

        <?php if ($showResults): ?>
            <?php if (isset($result) && $result->num_rows > 0): ?>
                <p class="mb-4">Number of Rows: <?php echo $numRows; ?></p>
                <div class="table-responsive">
                    <table class="table table-striped table-bordered">
                        <thead class="sticky-row">
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
                                        <button class="btn btn-secondary btn-sm copy-btn">Copy</button>
                                    </td>
                                    <?php foreach ($columns as $column): ?>
                                        <td class="whitespace-nowrap"><?php echo htmlspecialchars($row[$column]); ?></td>
                                    <?php endforeach; ?>
                                    
                                </tr>
                            <?php endwhile; ?>
                        </tbody>
                    </table>
                </div>
            <?php else: ?>
                <p class="text-center">No results found.</p>
            <?php endif; ?>
        <?php endif; ?>
    </div>
   
    <!-- Footer -->
    <footer class="bg-light mt-5 py-3">
        <div class="container text-center">
            <p class="mb-0">&copy; <?php echo date('Y'); ?> All rights reserved.</p>
        </div>
    </footer>

    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/js/bootstrap.bundle.min.js" integrity="sha384-HwwvtgBNo3bZJJLYd8oVXjrBZt8cqVSpeBNS5n7C8IVInixGAoxmnlMuBnhbgrkm" crossorigin="anonymous"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function () {
        // Copy button functionality
        document.querySelectorAll('.copy-btn').forEach(function(button) {
            button.addEventListener('click', function() {
                var row = this.closest('tr');
                var range = document.createRange();
                range.selectNode(row);
                window.getSelection().removeAllRanges();
                window.getSelection().addRange(range);
                document.execCommand('copy');
                window.getSelection().removeAllRanges();

                // Visual feedback
                this.textContent = 'Copied!';
                setTimeout(() => {
                    this.textContent = 'Copy';
                }, 1000);
            });
        });

        // Toggle Advanced Search
        const toggleButton = document.getElementById('toggleAdvancedSearch');
        const advancedSearchForm = document.getElementById('advancedSearchForm');
        
        toggleButton.addEventListener('click', () => {
            const ishid_newden = advancedSearchForm.style.display === 'none';
            advancedSearchForm.style.display = ishid_newden ? 'block' : 'none';
            toggleButton.textContent = ishid_newden ? 'hid_newe Advanced Search' : 'Show Advanced Search';
        });
    });

    function clearAdvancedSearch() {
        const inputs = document.querySelectorAll('input[name^="advanced_search"]');
        inputs.forEach(input => input.value = '');
    }
    </script>
</body>
</html>
<?php
$conn->close();
?>
