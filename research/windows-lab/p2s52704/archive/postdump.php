<?php
echo "count=" . count($_POST) . "\n";
foreach ($_POST as $k => $v) {
    if (is_string($v)) {
        echo "$k=" . strlen($v) . "\n";
    } else {
        echo "$k=ARRAY\n";
    }
}
