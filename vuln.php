<?php
// ========== PHP VULNERABILITIES ==========

// SQL Injection
$id = $_GET['id'];
$result = mysql_query("SELECT * FROM users WHERE id = '$id'");
$query = "SELECT * FROM accounts WHERE username = '$username' AND password = '$password'";

// XSS
echo $_GET['name'];

// RCE
eval($_GET['cmd']);

// LFI
include($_GET['page']);

// ========== JAVASCRIPT VULNERABILITIES ==========
?>
<script>
// XSS
document.write("<img src=x onerror=alert('XSS')>");
var input = location.hash;
document.write(input);

// Insecure eval with JSON
let user = eval('(' + '{"role":"admin"}' + ')');
</script>
<?php

// ========== PYTHON VULNERABILITIES ==========
$py = <<<PYTHON
import os

# Command Injection
cmd = input("Enter command: ")
os.system(cmd)

# Eval with untrusted data
import json
data = '{"name": "admin"}'
obj = eval(data)
PYTHON;

// ========== C VULNERABILITIES ==========
$c = <<<C
#include <stdio.h>
#include <stdlib.h>

int main() {
    char buf[100];

    // Buffer Overflow
    gets(buf);

    // Format string vuln
    printf(buf);

    // RCE
    system("ls -la");

    return 0;
}
C;

// ========== HTML VULNERABILITIES ==========
$html = <<<HTML
<html>
<body>
<script>
    var x = location.hash;
    document.write(x);
</script>
</body>
</html>
HTML;

// ========== JSON PAYLOAD (PSEUDO) ==========
$json = <<<JSON
{
    "payload": "eval(JSON.stringify({user: 'admin'}))"
}
JSON;
?>
