<?php
echo "PHP " . PHP_VERSION . " sapi=" . php_sapi_name() . "\n";
foreach (array(
    'memory_limit','post_max_size','upload_max_filesize','max_input_vars',
    'display_errors','session.use_cookies','session.use_strict_mode',
    'session.upload_progress.enabled','session.upload_progress.freq',
    'session.upload_progress.min_freq','session.sid_length','session.save_path',
) as $k) {
    echo $k . "=" . ini_get($k) . "\n";
}
