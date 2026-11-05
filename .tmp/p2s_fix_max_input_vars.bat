@echo off
setlocal enabledelayedexpansion
title php2shell — set max_input_vars=100000 on all 14 containers
echo ============================================
echo  php2shell config fix: max_input_vars=100000
echo  A1 in 860 depth-64 nested field = ~55040 nested var;
echo  default max_input_vars=1000 truncate ediyor. Yukselt.
echo ============================================
echo.

docker info >nul 2>&1
if errorlevel 1 ( echo [HATA] Docker calismiyor. & exit /b 1 )

echo [1] 14 container'da max_input_vars=100000 + display_errors=Off...
docker ps --filter "name=p2s" --format "{{.Names}}" | ForEach-Object {
  Write-Host "  $_ :"
  docker exec $_ sh -c "printf 'max_input_vars = 100000\ndisplay_errors = Off\n' > /usr/local/etc/php/conf.d/zz_p2s_fix.ini"
  docker exec $_ sh -c "apachectl -k graceful 2>/dev/null || service apache2 graceful 2>/dev/null || kill -USR2 1 2>/dev/null"
  timeout /t 1 >nul
}
echo.

echo [2] Dogrula:
echo ============================================
$map = @{ "5.4.45"="18101"; "5.5.38"="18102"; "5.6.40"="18103"; "7.0.33"="18104"; "7.1.33"="18105"; "7.2.34"="18106"; "7.3.33"="18107"; "7.4.33"="18108"; "8.0.30"="18109"; "8.1.32"="18110"; "8.2.34"="18111"; "8.3.35"="18112"; "8.4.26"="18113"; "8.5.11"="18114" }
foreach ($v in ($map.Keys | Sort-Object)) {
  $port = $map[$v]
  $mi = curl -s --max-time 6 "http://127.0.0.1:$port/p2s_probe.php" 2>$null | Select-String "max_input_vars"
  $de = curl -s --max-time 6 "http://127.0.0.1:$port/p2s_probe.php" 2>$null | Select-String "display_errors"
  Write-Host ("  PHP {0,-8} {1}  {2}" -f $v, $mi, $de)
}
echo.
echo ============================================
echo  Bitti. Mac'ten exploit'i tekrar calistir.
echo ============================================
endlocal
pause
