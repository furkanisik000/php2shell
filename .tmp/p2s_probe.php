<?php
/* php2shell config-probe: hedefin exploit-relevant config + ortam degerlerini cikarir.
   Exploit (9bie) Debian 13 + 128M memory_limit + display_errors=Off varsayiyor.
   Bu sayfa, hedefin GERCEK degerlerini gosterir. */
$g = function($k){ return ini_get($k); };
$out = array(
  "php_version"      => PHP_VERSION,
  "php_sapi"         => php_sapi_name(),
  "memory_limit"     => $g("memory_limit"),
  "post_max_size"    => $g("post_max_size"),
  "upload_max_filesize" => $g("upload_max_filesize"),
  "max_input_vars"   => $g("max_input_vars"),
  "max_execution_time" => $g("max_execution_time"),
  "display_errors"   => $g("display_errors"),
  "session.use_strict_mode" => $g("session.use_strict_mode"),
  "session.cookie_httponly" => $g("session.cookie_httponly"),
  "server_software"=> $_SERVER["SERVER_SOFTWARE"] ?? "?",
  "os"               => PHP_OS,
  "glibc"            => @shell_exec("ldd --version 2>/dev/null | head -1") ?: "?",
  "debian_version"   => @file_get_contents("/etc/debian_version") ?: "?",
  "uname"            => @shell_exec("uname -a") ?: "?",
  "whoami"           => @shell_exec("whoami 2>/dev/null") ?: "?",
);
header("Content-Type: text/plain");
foreach ($out as $k => $v) {
  printf("%-22s %s\n", $k . ":", trim((string)$v));
}
echo "\n--- full phpinfo (ilk 40 satir) ---\n";
ob_start(); phpinfo(); $p = ob_get_clean();
echo implode("\n", array_slice(explode("\n", $p), 0, 40)) . "\n";
