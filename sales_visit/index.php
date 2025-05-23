<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Generate Selenium Script</title>
</head>
<body>
    <h2>Generate Selenium Script</h2>
    <form action="generateSeleniumScript.php" method="post">
        
        <label for="home_id">Enter Home IDs:</label><br>
        <textarea name="home_id" id="home_id" rows="10" cols="50"></textarea><br><br>
        <label for="response">Enter Response:</label><br>
        <textarea name="response" id="response" rows="10" cols="50"></textarea><br>
        <input type="submit" value="Generate Script">
    </form>
    
   
</body>
</html>