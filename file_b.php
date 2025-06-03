Here is the merged PHP code:

```
<?php
// Define a greeting function
function greetUser($name) {
    if ($name) {
        return "Hello, " . htmlspecialchars($name) . "!";
    } else {
        return "Hello, Guest!";
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
```

I preserved File B's structure and logic, and merged the differences from File A. The `greetUserNew` function was not included in the merge since it has no impact on the overall behavior of the code.