<?php
// PHP Test Dataset - Web Security Vulnerabilities
// File: vulnerable_php.php

// VULNERABILITY 1: SQL Injection
function vulnerableLogin($username, $password) {
    $conn = mysqli_connect("localhost", "root", "admin123", "users");
    
    // SQL injection vulnerability - no prepared statements
    $query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
    $result = mysqli_query($conn, $query);
    
    return mysqli_fetch_all($result);
}

// VULNERABILITY 2: XSS - Reflected
function vulnerableSearch() {
    $search_term = $_GET['q'];
    
    // XSS vulnerability - unescaped output
    echo "<h1>Search results for: " . $search_term . "</h1>";
}

// VULNERABILITY 3: Path Traversal
function vulnerableFileRead() {
    $filename = $_GET['file'];
    
    // Path traversal vulnerability
    $filepath = "/uploads/" . $filename;
    return file_get_contents($filepath);
}

// VULNERABILITY 4: Command Injection  
function vulnerableCommand() {
    $cmd = $_POST['command'];
    
    // Command injection vulnerability
    $output = shell_exec("ping " . $cmd);
    return $output;
}

// VULNERABILITY 5: Insecure File Upload
function vulnerableUpload() {
    if (isset($_FILES['upload'])) {
        $filename = $_FILES['upload']['name'];
        
        // No file type validation - allows any file
        move_uploaded_file($_FILES['upload']['tmp_name'], "/uploads/" . $filename);
        echo "File uploaded: " . $filename;
    }
}

// VULNERABILITY 6: Session Fixation
function vulnerableSessionStart() {
    // Session fixation vulnerability - no session regeneration
    if (isset($_GET['session_id'])) {
        session_id($_GET['session_id']);
    }
    session_start();
}

// VULNERABILITY 7: Weak Cryptography
function weakPasswordHash($password) {
    // MD5 is cryptographically broken
    return md5($password);
}

// VULNERABILITY 8: Information Disclosure
function vulnerableErrorHandling() {
    try {
        $conn = new PDO("mysql:host=localhost;dbname=users", "root", "wrongpassword");
    } catch (Exception $e) {
        // Exposing sensitive error information
        die("Database error: " . $e->getMessage());
    }
}

// VULNERABILITY 9: LDAP Injection
function vulnerableLDAPSearch($username) {
    $ldap_conn = ldap_connect("ldap://localhost");
    
    // LDAP injection vulnerability
    $search_filter = "(uid=" . $username . ")";
    $result = ldap_search($ldap_conn, "dc=example,dc=com", $search_filter);
    
    return ldap_get_entries($ldap_conn, $result);
}

// VULNERABILITY 10: Insecure Randomness
function weakTokenGeneration() {
    // Weak random number generation
    return md5(rand());
}

// VULNERABILITY 11: Hardcoded Credentials
$database_password = "admin123";
$api_secret = "sk-1234567890abcdef";

// VULNERABILITY 12: Eval Injection
function vulnerableEval() {
    $code = $_POST['code'];
    
    // Code injection via eval
    eval($code);
}

// VULNERABILITY 13: XXE (XML External Entity)
function vulnerableXMLParse() {
    $xml_data = $_POST['xml'];
    
    // XXE vulnerability - external entities enabled
    $xml = simplexml_load_string($xml_data);
    return $xml;
}

// VULNERABILITY 14: Open Redirect
function vulnerableRedirect() {
    $redirect_url = $_GET['url'];
    
    // Open redirect vulnerability
    header("Location: " . $redirect_url);
    exit();
}

// VULNERABILITY 15: Insecure Direct Object Reference
function vulnerableProfileAccess() {
    $user_id = $_GET['user_id'];
    
    // No authorization check
    $query = "SELECT * FROM profiles WHERE user_id = " . $user_id;
    // ... database query
}

?>
