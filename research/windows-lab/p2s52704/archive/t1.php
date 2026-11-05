<?php
echo "limit=" . ini_get("memory_limit") . "\n";
echo "before=" . round(memory_get_usage(true)/1048576, 2) . "M\n";
$s = str_repeat(chr(65), 12*1024*1024);
echo "after12M=" . round(memory_get_usage(true)/1048576, 2) . "M ok=" . strlen($s) . "\n";
