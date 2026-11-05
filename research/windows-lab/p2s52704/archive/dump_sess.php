<?php
// Dump script: shows the session state during reqB (after reqA's OOM).
// Place as index.php; send reqA (OOM) then reqB (with this as the handler).
session_start();
ob_start();
echo "=== POST fields ===\n";
foreach ($_POST as $k => $v) {
    if (is_string($v)) {
        $len = strlen($v);
        $prev = bin2hex(substr($v, 0, 32));
        echo "  [$k] len=$len prev=$prev\n";
    }
}
echo "=== _SESSION keys ===\n";
foreach (array_keys($_SESSION) as $k) { echo "  " . $k . "\n"; }
if (isset($_SESSION['1999'])) {
    $v = $_SESSION['1999'];
    if (is_string($v)) {
        echo "  [1999] len=" . strlen($v) . " hex=" . bin2hex(substr($v,0,32)) . "\n";
    }
}
$out = ob_get_clean();
// send via header so it doesn't interfere with the session cookie
header("X-Dump: " . base64_encode($out));
echo "OK";
