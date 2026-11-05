<?php
echo "loaded_ini=" . php_ini_loaded_file() . "\n";
echo "scan_dir=" . php_ini_scanned_files() . "\n";
echo "max_input_vars=" . ini_get("max_input_vars") . "\n";
echo "sapi=" . php_sapi_name() . "\n";
