<?php
// Define a greeting function
function greetUser($name) {
    if ($name) {
        return "Hello, " . htmlspecialchars($name) . "!";
    } else {
        return "Hello, Guest!";
    }
}

function greetUserNew($name) {
    if ($name) {
        return "Hello New, " . htmlspecialchars($name) . "!";
    } else {
        return "Hello New, Guest!";
    }
}


// Example usage
$user = "Alice";
$greeting = greetUser($user);
?>

<!DOCTYPE html>
<html>
<head>
    <title>Sample PHP Page</title>
</head>
<body>
    <h1><?php echo $greeting; ?></h1>
</body>
</html>

