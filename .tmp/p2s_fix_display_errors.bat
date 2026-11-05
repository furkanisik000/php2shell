@echo off
setlocal enabledelayedexpansion
title php2shell — set display_errors=Off on all 14 containers
echo ============================================
echo  php2shell config fix: display_errors=Off
echo  Exploit Off varsayiyor; hedef On. Duzelt + Apache restart.
echo ============================================
echo.

docker info >nul 2>&1
if errorlevel 1 ( echo [HATA] Docker calismiyor. & exit /b 1 )

echo [1] 14 container'da display_errors=Off + Apache restart...
docker ps --filter "name=p2s" --format "{{.Names}}" | ForEach-Object {
  Write-Host "  $_ :"
  docker exec $_ sh -c "sed -i 's/^;\?display_errors\s*=.*/display_errors = Off/' /usr/local/etc/php/php.ini 2>/dev/null || echo 'display_errors = Off' >> /usr/local/etc/php/php.ini"
  docker exec $_ sh -c "apachectl -k graceful 2>/dev/null || service apache2 graceful 2>/dev/null || kill -USR2 1 2>/dev/null"
  timeout /t 1 >nul
}
echo.

echo [2] Dogrula (display_errors degeri):
echo ============================================
$map = @{ "5.4.45"="18101"; "5.5.38"="18102"; "5.6.40"="18103"; "7.0.33"="18104"; "7.1.33"="18105"; "7.2.34"="18106"; "7.3.33"="18107"; "7.4.33"="18108"; "8.0.30"="18109"; "8.1.32"="18110"; "8.2.34"="18111"; "8.3.35"="18112"; "8.4.26"="18113"; "8.5.11"="18114" }
foreach ($v in ($map.Keys | Sort-Object)) {
  $port = $map[$v]
  $line = curl -s --max-time 6 "http://127.0.0.1:$port/p2s_probe.php" 2>$null | Select-String "display_errors"
  Write-Host ("  PHP {0,-8} {1}" -f $v, $line)
}
echo.
echo ============================================
echo  Bitti. Simdi Mac'ten exploit'i tekrar calistir.
echo ============================================
endlocal
pause
