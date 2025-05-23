<script src="https://cdn.tailwindcss.com"></script>

<style>
    .flex-center {
        display: flex;
        justify-content: center;
        align-items: center;
        height: 10vh;
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
<div class="flex-center">
    <div class="form-container">
        <form method="GET" action="">
            <input type="text" name="search" placeholder="Search" class="px-4 py-2 search-input">
            <button type="submit" class="px-4 py-2 bg-blue-500 text-white">Search</button>
        </form>
    </div>
</div>


<?php
ini_set('max_execution_time', 300);
require_once __DIR__ . '/vendor/autoload.php';

if (isset($_GET['search'])) {
    $searchTerm = $_GET['search'];
    $apiKey = 'AIzaSyCAgB-lEraYjbo3do9QOrBsj-geL78nlw8';
    $spreadsheetId = '1IMhK23gUQEB1MDCAUdg4LZ6-2fQM40TgGji8IGaPllM';

    $client = new Google_Client();
    $client->setApplicationName('Google Sheets API PHP');
    $client->setAccessType('offline');
    $client->setDeveloperKey($apiKey);

    $service = new Google_Service_Sheets($client);

    $sheetsResponse = $service->spreadsheets->get($spreadsheetId);
    $sheets = $sheetsResponse->getSheets();
    $sheetNames = [];
    foreach ($sheets as $sheet) {
        $sheetProperties = $sheet->getProperties();
        $sheetNames[] = $sheetProperties->getTitle();
    }

    $searchResults = [];

    foreach ($sheetNames as $sheetName) {
        $range = $sheetName . '!A1:L';
        $response = $service->spreadsheets_values->get($spreadsheetId, $range);
        $values = $response->getValues();

        if (!empty($values)) {
            $sheetSearchResults = searchInSheet($values, $searchTerm);
            $searchResults = array_merge($searchResults, $sheetSearchResults);
        }
    }

    $numRows = count($searchResults);

    if ($numRows > 0) {
        echo '<p class="mb-4">Jumlah Baris: ' . $numRows . '</p>';
        echo '<div class="overflow-x-auto">';
        echo '<table class="table-auto min-w-full">';
        echo '<tr>';
        echo '<th class="px-4 py-2">#</th>';
        echo '<th class="px-4 py-2">Province</th>';
        echo '<th class="px-4 py-2">City</th>';
        echo '<th class="px-4 py-2">Subdistrict</th>';
        echo '<th class="px-4 py-2">Village</th>';
        echo '<th class="px-4 py-2">Apartment/Cluster</th>';
        echo '<th class="px-4 py-2">Tower/Block</th>';
        echo '<th class="px-4 py-2">Floor</th>';
        echo '<th class="px-4 py-2">No</th>';
        echo '<th class="px-4 py-2">HomeID</th>';
        echo '<th class="px-4 py-2">Project ID</th>';
        echo '<th class="px-4 py-2">Project Name</th>';
        echo '<th class="px-4 py-2">Status</th>';
        echo '</tr>';

        for ($i = 0; $i < $numRows; $i++) {
            $row = $searchResults[$i];
            echo '<tr>';
            echo '<td class="border px-4 py-2 whitespace-nowrap">' . ($i + 1) . '</td>';
            foreach ($row as $cellValue) {
                echo '<td class="border px-4 py-2 whitespace-nowrap">' . $cellValue . '</td>';
            }
            echo '</tr>';
        }
        echo '</table>';
        echo '</div>';
    } else {
        echo '<p class="mb-4">Hasil pencarian tidak ditemukan.</p>';
    }
}

function searchInSheet($values, $searchTerm) {
    $searchResults = [];
    $numColumns = count($values[0]);

    foreach ($values as $row) {
        $found = false; // Flag untuk melacak jika ada kecocokan dalam baris

        foreach ($row as $cellValue) {
            if (stripos($cellValue, $searchTerm) !== false) {
                $found = true;
                break; // Keluar dari perulangan dalam
            }
        }

        if ($found) {
            $searchResults[] = $row;
        }
    }

    return $searchResults;
}
?>