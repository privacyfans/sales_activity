<?php

ob_start(); // Start buffering

include 'randomData.php';

// Mengambil parameter home_id dari POST data
//$home_ids = explode("\n", str_replace("\r", "", $_POST['home_id']));
//$status = $_POST['status'];

 $text = $_POST["home_id"];

 
    $home_ids = [];
    $status = "";

   $home_ids = [];
    $status = "";


    // Pencocokan regex untuk menemukan semua elemen <li>
    preg_match_all('/<li class="select2-results__option.*?>(.*?)<\/li>/', $text, $li_matches);
    foreach ($li_matches[1] as $li_content) {
        // Pencocokan regex untuk menemukan ID di dalam elemen <li>
        if (preg_match('/\((\d{5}[A-Z]\d{3}\.\d\.\d{5})\)/', $li_content, $id_match) || preg_match('/\((\d{5}[A-Z]\d{6})\)/', $li_content, $id_match)) {
            $id = $id_match[1];
            // Cek apakah ada kata "Occupied" di dalam elemen <li>
            if (strpos($li_content, 'Occupied') !== false) {
                $home_ids[] = $id . "~";
                $status = "occupied";
            } else {
                $home_ids[] = $id;
            }
        }
    }
    
 $home_ids_clear= str_replace('~', '', $home_ids);
 $response = $_POST["response"];
 $final_home_ids=[];
 if($response != ""){
        preg_match_all('/"home_id":\s*"([^"]+)"/', $response, $matches);
        $home_id_response = $matches[1];
        $diff_home_ids = array_diff($home_ids_clear, $home_id_response);
        $home_ids = [];
        foreach ($diff_home_ids as $diff_id) {
            if (in_array($diff_id . "~", $home_ids)) {
                $final_home_ids[] = $diff_id . "~";
            } else {
                $final_home_ids[] = $diff_id;
            }
        }
       $home_ids=$final_home_ids;
 }

$result = "";

$jumlah = count($home_ids);

$counter = 0;
$header='{
    "id": "8819216f-c2ca-4fcc-9833-5ccf1fa010be",
    "version": "2.0",
    "name": "sales_visit",
    "url": "https://salesvisit.cbn.net.id/",
    "tests": [';

$remark="";
foreach ($home_ids as $index => $home_id) {
     if (strpos($home_id, '~') !== false) {
    $result = "SUDAH AKTIF DI CBN";
    $remark="-";
} else {
    /*$randomValue = mt_rand(1, 100); // Generate a random number between 1 and 100

        // Adjust the probability for "KEMAHALAN"
        $probabilityOfKemahalan = 50;

        if ($randomValue <= $probabilityOfKemahalan) {
            $result = "KEMAHALAN";
            $remark="KEBERATAN BIAYA PASANG, BANYAK PROVIDER LAIN YANG FREE INSTALASI";
        } else {*/
            $nonOccupiedResults = [
                "CUSTOMER TIDAK DI TEMPAT",
                "CUSTOMER TIDAK BERMINAT",
                "SUDAH MENGGUNAKAN ISP LAIN",
                "PIKIR-PIKIR/DISKUSI DENGAN PEMILIK/KELUARGA"
            ];
            $result = $nonOccupiedResults[array_rand($nonOccupiedResults)];
            $remark="-";
        //}
}
$home_id = str_replace("~", "", $home_id);
   $counter++;
    $body.='
	{"id": "eb1b2516-cf05-4bbf-8e69-7b8dd214b92c",
    "name": "'.$home_id.'",
    "commands": 
	[{
      "id": "80eec233-766d-45da-b1c7-65cd2f88c239",
      "comment": "",
      "command": "open",
      "target": "/MenuWeb",
      "targets": [],
      "value": ""
    }, {
      "id": "ac988e57-c07e-476b-81f3-2d2585bfe44e",
      "comment": "",
      "command": "setWindowSize",
      "target": "986x807",
      "targets": [],
      "value": ""
    }, {
      "id": "1668583e-c485-41d5-b264-c5bcb814f59a",
      "comment": "",
      "command": "click",
      "target": "css=.bi-briefcase",
      "targets": [
        ["css=.bi-briefcase", "css:finder"],
        ["xpath=//div/i", "xpath:position"]
      ],
      "value": ""
    }, {
      "id": "575d62dc-720f-45a0-a3d3-02f0a7af8ce1",
      "comment": "",
      "command": "click",
      "target": "id=select2-inptHomeId-container",
      "targets": [
        ["id=select2-inptHomeId-container", "id"],
        ["css=#select2-inptHomeId-container", "css:finder"],
        ["xpath=//span[@id=\'select2-inptHomeId-container\']", "xpath:attributes"],
        ["xpath=//form[@id=\'frmSalesVisiting\']/div/span/span/span/span", "xpath:idRelative"],
        ["xpath=//span/span/span/span", "xpath:position"]
      ],
      "value": ""
    }, {
      "id": "dff90a5a-4f72-4689-bb57-49235f321cfe",
      "comment": "",
      "command": "type",
      "target": "css=.select2-search__field",
      "targets": [
        ["css=.select2-search__field", "css:finder"],
        ["xpath=//input[@type=\'search\']", "xpath:attributes"],
        ["xpath=//span/input", "xpath:position"]
      ],
      "value": "'.$home_id.'"
    }, {
      "id": "39269d88-b263-4475-ba36-9599ed05012d",
      "comment": "",
      "command": "sendKeys",
      "target": "css=.select2-search__field",
      "targets": [
        ["css=.select2-search__field", "css:finder"],
        ["xpath=//input[@type=\'search\']", "xpath:attributes"],
        ["xpath=//span/input", "xpath:position"]
      ],
      "value": "${KEY_ENTER}"
    }, {
      "id": "17d1971e-653b-47b8-ab00-48ca0a7c1b17",
      "comment": "",
      "command": "click",
      "target": "id=inptCustomerName",
      "targets": [
        ["id=inptCustomerName", "id"],
        ["name=NamaCustomer", "name"],
        ["css=#inptCustomerName", "css:finder"],
        ["xpath=//input[@id=\'inptCustomerName\']", "xpath:attributes"],
        ["xpath=//form[@id=\'frmSalesVisiting\']/div[3]/input", "xpath:idRelative"],
        ["xpath=//div[3]/input", "xpath:position"]
      ],
      "value": ""
    }, {
      "id": "6bec7779-013f-4891-8f81-da11884d1776",
      "comment": "",
      "command": "click",
      "target": "id=inptCustomerName",
      "targets": [
        ["id=inptCustomerName", "id"],
        ["name=NamaCustomer", "name"],
        ["css=#inptCustomerName", "css:finder"],
        ["xpath=//input[@id=\'inptCustomerName\']", "xpath:attributes"],
        ["xpath=//form[@id=\'frmSalesVisiting\']/div[3]/input", "xpath:idRelative"],
        ["xpath=//div[3]/input", "xpath:position"]
      ],
      "value": ""
    }, {
      "id": "6d41adcd-86f0-4d8a-a603-3e993ec11837",
      "comment": "",
      "command": "type",
      "target": "id=inptCustomerName",
      "targets": [
        ["id=inptCustomerName", "id"],
        ["name=NamaCustomer", "name"],
        ["css=#inptCustomerName", "css:finder"],
        ["xpath=//input[@id=\'inptCustomerName\']", "xpath:attributes"],
        ["xpath=//form[@id=\'frmSalesVisiting\']/div[3]/input", "xpath:idRelative"],
        ["xpath=//div[3]/input", "xpath:position"]
      ],
      "value": "'.generateRandomName().'"
    }, {
      "id": "3303a7b7-79c4-4834-93b9-724ed0d3d8e1",
      "comment": "",
      "command": "click",
      "target": "id=inptCustomerTelp",
      "targets": [
        ["id=inptCustomerTelp", "id"],
        ["name=TelpNoCustomer", "name"],
        ["css=#inptCustomerTelp", "css:finder"],
        ["xpath=//input[@id=\'inptCustomerTelp\']", "xpath:attributes"],
        ["xpath=//form[@id=\'frmSalesVisiting\']/div[4]/input", "xpath:idRelative"],
        ["xpath=//div[4]/input", "xpath:position"]
      ],
      "value": ""
    }, {
      "id": "931f3a43-dc32-4e53-ab1f-78053834ef29",
      "comment": "",
      "command": "click",
      "target": "id=inptCustomerTelp",
      "targets": [
        ["id=inptCustomerTelp", "id"],
        ["name=TelpNoCustomer", "name"],
        ["css=#inptCustomerTelp", "css:finder"],
        ["xpath=//input[@id=\'inptCustomerTelp\']", "xpath:attributes"],
        ["xpath=//form[@id=\'frmSalesVisiting\']/div[4]/input", "xpath:idRelative"],
        ["xpath=//div[4]/input", "xpath:position"]
      ],
      "value": ""
    }, {
      "id": "972e64f8-1420-4bcf-b607-8084e1e6c1b5",
      "comment": "",
      "command": "type",
      "target": "id=inptCustomerTelp",
      "targets": [
        ["id=inptCustomerTelp", "id"],
        ["name=TelpNoCustomer", "name"],
        ["css=#inptCustomerTelp", "css:finder"],
        ["xpath=//input[@id=\'inptCustomerTelp\']", "xpath:attributes"],
        ["xpath=//form[@id=\'frmSalesVisiting\']/div[4]/input", "xpath:idRelative"],
        ["xpath=//div[4]/input", "xpath:position"]
      ],
      "value": "'.generateRandomPhoneNumber().'"
    }, {
          "id": "108d302a-0989-436d-9dca-10df75076566",
          "comment": "",
          "command": "click",
          "target": "css=#select2-inptTypeBuilding-container > .select2-selection__placeholder",
          "targets": [
            ["css=#select2-inptTypeBuilding-container > .select2-selection__placeholder", "css:finder"],
            ["xpath=//span[@id=\'select2-inptTypeBuilding-container\']/span", "xpath:idRelative"],
            ["xpath=//div[8]/span/span/span/span/span", "xpath:position"]
          ],
          "value": ""
        }, {
          "id": "ec73d64f-e9d0-4bd4-aede-ebcbb15a1d5a",
          "comment": "",
          "command": "type",
          "target": "css=.select2-search__field",
          "targets": [
            ["css=.select2-search__field", "css:finder"],
            ["xpath=//input[@type=\'search\']", "xpath:attributes"],
            ["xpath=//span/input", "xpath:position"]
          ],
          "value": "re"
        }, {
          "id": "5a32ab6c-6d2a-455c-ae26-4d0a830ed102",
          "comment": "",
          "command": "sendKeys",
          "target": "css=.select2-search__field",
          "targets": [
            ["css=.select2-search__field", "css:finder"],
            ["xpath=//input[@type=\'search\']", "xpath:attributes"],
            ["xpath=//span/input", "xpath:position"]
          ],
          "value": "${KEY_ENTER}"
        }, {
          "id": "19b57d93-4db7-4ab0-9187-a119a372f34c",
          "comment": "",
          "command": "runScript",
          "target": "window.scrollTo(0,418.3999938964844)",
          "targets": [],
          "value": ""
        }, {
          "id": "668cc170-c92e-4926-9386-1be755df05e2",
          "comment": "",
          "command": "click",
          "target": "css=#select2-inptActivity-container > .select2-selection__placeholder",
          "targets": [
            ["css=#select2-inptActivity-container > .select2-selection__placeholder", "css:finder"],
            ["xpath=//span[@id=\'select2-inptActivity-container\']/span", "xpath:idRelative"],
            ["xpath=//div[9]/span/span/span/span/span", "xpath:position"]
          ],
          "value": ""
        }, {
          "id": "fa30a7db-f571-4a6a-90cd-0858c25ebabe",
          "comment": "",
          "command": "type",
          "target": "css=.select2-search__field",
          "targets": [
            ["css=.select2-search__field", "css:finder"],
            ["xpath=//input[@type=\'search\']", "xpath:attributes"],
            ["xpath=//span/input", "xpath:position"]
          ],
          "value": "PROBING"
        }, {
          "id": "62f76e98-b680-463c-adfc-9560ee10142f",
          "comment": "",
          "command": "sendKeys",
          "target": "css=.select2-search__field",
          "targets": [
            ["css=.select2-search__field", "css:finder"],
            ["xpath=//input[@type=\'search\']", "xpath:attributes"],
            ["xpath=//span/input", "xpath:position"]
          ],
          "value": "${KEY_ENTER}"
        }, {
          "id": "33a3bbd3-1f2d-4b59-a27d-8e784110f80c",
          "comment": "",
          "command": "click",
          "target": "id=select2-inptResult-container",
          "targets": [
            ["id=select2-inptResult-container", "id"],
            ["css=#select2-inptResult-container", "css:finder"],
            ["xpath=//span[@id=\'select2-inptResult-container\']", "xpath:attributes"],
            ["xpath=//form[@id=\'frmSalesVisiting\']/div[11]/span/span/span/span", "xpath:idRelative"],
            ["xpath=//div[11]/span/span/span/span", "xpath:position"]
          ],
          "value": ""
        }, {
          "id": "c76ab331-7377-4e53-9f3c-8479feb5d853",
          "comment": "",
          "command": "type",
          "target": "css=.select2-search__field",
          "targets": [
            ["css=.select2-search__field", "css:finder"],
            ["xpath=//input[@type=\'search\']", "xpath:attributes"],
            ["xpath=//span/input", "xpath:position"]
          ],
          "value": "'.$result.'"
        }, {
          "id": "494410e0-6009-4acc-8191-6fcd8ed4dab4",
          "comment": "",
          "command": "sendKeys",
          "target": "css=.select2-search__field",
          "targets": [
            ["css=.select2-search__field", "css:finder"],
            ["xpath=//input[@type=\'search\']", "xpath:attributes"],
            ["xpath=//span/input", "xpath:position"]
          ],
          "value": "${KEY_ENTER}"
        }, {
          "id": "f2a1d83d-7af7-43b3-a165-3f1849272e3b",
          "comment": "",
          "command": "click",
          "target": "css=#select2-inptProviderExisting-container > .select2-selection__placeholder",
          "targets": [
            ["css=#select2-inptProviderExisting-container > .select2-selection__placeholder", "css:finder"],
            ["xpath=//span[@id=\'select2-inptProviderExisting-container\']/span", "xpath:idRelative"],
            ["xpath=//div[12]/span/span/span/span/span", "xpath:position"]
          ],
          "value": ""
        }, {
          "id": "dd196ce9-04bf-45c1-9c32-810ffa442838",
          "comment": "",
          "command": "type",
          "target": "css=.select2-search__field",
          "targets": [
            ["css=.select2-search__field", "css:finder"],
            ["xpath=//input[@type=\'search\']", "xpath:attributes"],
            ["xpath=//span/input", "xpath:position"]
          ],
          "value": "INDIHOME"
        }, {
          "id": "2979d186-b7ca-48d3-9cb7-367c16263706",
          "comment": "",
          "command": "sendKeys",
          "target": "css=.select2-search__field",
          "targets": [
            ["css=.select2-search__field", "css:finder"],
            ["xpath=//input[@type=\'search\']", "xpath:attributes"],
            ["xpath=//span/input", "xpath:position"]
          ],
          "value": "${KEY_ENTER}"
        }, {
          "id": "b9dfac3d-7c5d-44f4-8d28-f10106b989ef",
          "comment": "",
          "command": "click",
          "target": "css=.select2-selection__placeholder",
          "targets": [
            ["css=.select2-selection__placeholder", "css:finder"],
            ["xpath=//span[@id=\'select2-inptProductType-container\']/span", "xpath:idRelative"],
            ["xpath=//div[14]/span/span/span/span/span", "xpath:position"]
          ],
          "value": ""
        }, {
          "id": "6ebd5419-b61a-4adb-b7db-65c671408314",
          "comment": "",
          "command": "type",
          "target": "css=.select2-search__field",
          "targets": [
            ["css=.select2-search__field", "css:finder"],
            ["xpath=//input[@type=\'search\']", "xpath:attributes"],
            ["xpath=//span/input", "xpath:position"]
          ],
          "value": "50"
        }, {
          "id": "63df2111-26ee-41dc-8ea2-d08c11a6960a",
          "comment": "",
          "command": "sendKeys",
          "target": "css=.select2-search__field",
          "targets": [
            ["css=.select2-search__field", "css:finder"],
            ["xpath=//input[@type=\'search\']", "xpath:attributes"],
            ["xpath=//span/input", "xpath:position"]
          ],
          "value": "${KEY_ENTER}"
        }, {
          "id": "a6898c3b-09fa-4358-ac57-b41923b8b6a1",
          "comment": "",
          "command": "click",
          "target": "id=inptNotes",
          "targets": [
            ["id=inptNotes", "id"],
            ["name=Notes", "name"],
            ["css=#inptNotes", "css:finder"],
            ["xpath=//textarea[@id=\'inptNotes\']", "xpath:attributes"],
            ["xpath=//form[@id=\'frmSalesVisiting\']/div[15]/textarea", "xpath:idRelative"],
            ["xpath=//textarea", "xpath:position"]
          ],
          "value": ""
        }, {
          "id": "4e45f252-8bc5-4123-97d8-e54cf25df8c5",
          "comment": "",
          "command": "type",
          "target": "id=inptNotes",
          "targets": [
            ["id=inptNotes", "id"],
            ["name=Notes", "name"],
            ["css=#inptNotes", "css:finder"],
            ["xpath=//textarea[@id=\'inptNotes\']", "xpath:attributes"],
            ["xpath=//form[@id=\'frmSalesVisiting\']/div[15]/textarea", "xpath:idRelative"],
            ["xpath=//textarea", "xpath:position"]
          ],
          "value": "'.$remark.'"
        }, {
          "id": "0f86b46e-8e66-490b-93c8-b28b530ba59e",
          "comment": "",
          "command": "click",
          "target": "id=btnSubmitForm",
          "targets": [
            ["id=btnSubmitForm", "id"],
            ["css=#btnSubmitForm", "css:finder"],
            ["xpath=//button[@id=\'btnSubmitForm\']", "xpath:attributes"],
            ["xpath=//form[@id=\'frmSalesVisiting\']/button", "xpath:idRelative"],
            ["xpath=//form/button", "xpath:position"],
            ["xpath=//button[contains(.,\'Save\')]", "xpath:innerText"]
          ],
          "value": ""
        }, {
          "id": "c23cc6c8-70c9-4954-a0e5-09cef2a9867b",
          "comment": "",
          "command": "click",
          "target": "css=.confirm",
          "targets": [
            ["css=.confirm", "css:finder"],
            ["xpath=//div[7]/div/button", "xpath:position"],
            ["xpath=//button[contains(.,\'OK\')]", "xpath:innerText"]
          ],
          "value": ""
        }, {
          "id": "e36eba5a-2e75-4d75-9249-2a19fd985edf",
          "comment": "",
          "command": "click",
          "target": "css=.bi-arrow-left-short > path",
          "targets": [
            ["css=.bi-arrow-left-short > path", "css:finder"]
          ],
          "value": ""
        }, {
            "id": "6cf2b747-3f22-449f-a11c-cb8596b4b9a6",
            "comment": "",
            "command": "close",
            "target": "",
            "targets": [],
            "value": ""
          }]
      }';
      if ($counter != $jumlah) {
        $body .= ",";
      }
}
$footer='],
"suites": [{
  "id": "092bd2f3-f1da-4837-bfdd-5daed93008c0",
  "name": "Default Suite",
  "persistSession": false,
  "parallel": false,
  "timeout": 300,
  "tests": ["b112f5ed-45df-47ec-827a-9e483ec4e4b4"]
}],
"urls": ["https://salesvisit.cbn.net.id/"],
"plugins": []
}';

// Set headers
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment;filename="sales_visit"'.date('YmdHis').'".side"');
ob_end_flush(); // Flush and end buffering
echo $header.$body.$footer;

?>
