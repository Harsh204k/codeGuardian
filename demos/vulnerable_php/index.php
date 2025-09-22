<?php
  $name = $_GET["name"]; // user input
  echo $name; // PHP-XSS-001
  $sql = "SELECT * FROM users WHERE id=" . $_GET["id"]; // PHP-SQLI-001
  mysqli_query($conn, $sql);
?>
