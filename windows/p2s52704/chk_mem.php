<?php
// Check if the big field is actually stored in memory
error_reporting(E_ALL);
ini_set('display_errors', 1);
echo "memory_limit: " . ini_get('memory_limit') . "\n";
echo "post_max_size: " . ini_get('post_max_size') . "\n";
echo "upload_max_filesize: " . ini_get('upload_max_filesize') . "\n";
echo "max_input_vars: " . ini_get('max_input_vars') . "\n";
echo "\n--- POST fields ---\n";
$count = count($_POST);
echo "field count: $count\n";
$total = 0;
foreach ($_POST as $k => $v) {
    if (is_string($v)) {
        $len = strlen($v);
        $total += $len;
        if ($len > 1000) {
            echo "  $k: " . $len . " bytes\n";
        }
    }
}
echo "total POST size: " . $total . " bytes (" . round($total/1024/1024, 1) . " MB)\n";
echo "\nmemory_usage: " . round(memory_get_usage(true)/1024/1024, 1) . " MB\n";
echo "memory_peak: " . round(memory_get_peak_usage(true)/1024/1024, 1) . " MB\n";
?>
