<?php
// Vulnerable PHP Application Demo
echo "<h1>=== Vulnerable PHP Application Demo ===</h1>";

// Hardcoded credentials - major security risk
$DB_PASSWORD = "root123!"; // PHP-HARDCRED-001
$API_KEY = "sk-1234567890abcdef1234567890abcdef"; // PHP-HARDCRED-002

// Get user input from various sources
$userId = $_GET['id'] ?? $_POST['id'] ?? '1';
$userName = $_GET['name'] ?? $_POST['name'] ?? 'admin';
$email = $_GET['email'] ?? $_POST['email'] ?? 'admin@example.com';
$fileName = $_GET['file'] ?? $_POST['file'] ?? 'config.txt';
$cmd = $_GET['cmd'] ?? $_POST['cmd'] ?? 'ls';

// SQL Injection vulnerability
$conn = mysqli_connect("localhost", "root", $DB_PASSWORD, "myapp");
$sql = "SELECT * FROM users WHERE id = " . $userId . " AND name = '" . $userName . "'"; // PHP-SQLI-001
$result = mysqli_query($conn, $sql);

// XSS vulnerability - direct output without sanitization
echo "<div>Welcome " . $userName . "</div>"; // PHP-XSS-001

// Command injection vulnerability
$output = shell_exec("ls -la " . $cmd); // PHP-CMDI-001
echo "<pre>Command output: " . $output . "</pre>";

// Path traversal vulnerability
$fullPath = "uploads/" . $fileName; // PHP-PATH-001
if (file_exists($fullPath)) {
    $content = file_get_contents($fullPath);
    echo "<p>File content: " . htmlspecialchars($content) . "</p>";
}

// File inclusion vulnerability
$page = $_GET['page'] ?? 'home';
include($page . '.php'); // PHP-FI-001

// Weak random number generation
session_start();
$_SESSION['token'] = rand(1000, 9999); // PHP-WEAKRAND-001
echo "<p>Session token: " . $_SESSION['token'] . "</p>";

// Insecure deserialization
if (isset($_POST['data'])) {
    $data = unserialize($_POST['data']); // PHP-DESER-001
    echo "<p>Deserialized data: " . print_r($data, true) . "</p>";
}

// Weak encryption example
function encryptPassword($password) {
    // Simple XOR "encryption" - completely insecure
    $encrypted = '';
    for ($i = 0; $i < strlen($password); $i++) {
        $encrypted .= chr(ord($password[$i]) ^ 0x55); // PHP-WEAKENC-001
    }
    return $encrypted;
}

$encryptedPass = encryptPassword($userName);
echo "<p>Encrypted password: " . $encryptedPass . "</p>";

// Eval vulnerability (very dangerous)
$code = $_GET['code'] ?? 'echo "Hello";';
eval($code); // PHP-EVAL-001

// Buffer overflow simulation with arrays
$buffer = array_fill(0, 10, 0);
for ($i = 0; $i < 15; $i++) { // PHP-BUFFER-001
    $buffer[$i] = $i;
}

// Null pointer dereference simulation
$nullVar = null;
if ($userName === 'crash') {
    $nullVar = null;
}
echo "<p>Variable length: " . strlen($nullVar) . "</p>"; // PHP-NULLPTR-001

// Hardcoded API call simulation
function callAPI($apiKey) {
    // In real code, this would make an HTTP request
    echo "<p>Calling API with key: " . substr($apiKey, 0, 10) . "...</p>";
}

callAPI($API_KEY);

echo "<p>Application completed</p>";
?>
