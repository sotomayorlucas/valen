<?php
// CWE-78: OS command injection via query parameter.
if (isset($_GET['cmd'])) {
    $q = $_GET['cmd'];
    system($q);
}

// CWE-74: file inclusion of user-controlled path.
$page = $_REQUEST['page'];
include($page);

// CWE-89-style raw query with request input.
$conn = mysqli_connect("localhost", "root", "", "app");
$sql = "SELECT * FROM users WHERE name = '" . $_GET['name'] . "'";
mysqli_query($conn, $sql);
