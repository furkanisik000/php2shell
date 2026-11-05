@echo off
setlocal enabledelayedexpansion
title php2shell — max_input_vars fix (ana php.ini + conf.d + Apache php_value)
echo ============================================
echo  max_input_vars=100000 (3 yol: php.ini, conf.d, Apache php_value)
echo ============================================
echo.
docker info >nul 2>&1
if errorlevel 1 ( echo [HATA] Docker calismiyor. & exit /b 1 )

docker ps --filter "name=p2s" --format "{{.Names}}" | ForEach-Object {
  Write-Host "  $_ :"
  $c = $_
  REM 1) ana php.ini'ye ekle
  docker exec $c sh -c "grep -q '^max_input_vars' /usr/local/etc/php/php.ini 2>/dev/null && sed -i 's/^max_input_vars.*/max_input_vars = 100000/' /usr/local/etc/php/php.ini || echo 'max_input_vars = 100000' >> /usr/local/etc/php/php.ini"
  REM 2) conf.d'ye de koymustur, kontrol et
  docker exec $c sh -c "echo 'max_input_vars = 100000' > /usr/local/etc/php/conf.d/99_p2s_maxinput.ini 2>/dev/null"
  REM 3) Apache php_value (mod_php)
  docker exec $c sh -c "echo 'php_value max_input_vars 100000' > /etc/apache2/conf-enabled/p2s_maxinput.conf 2>/dev/null; echo 'php_value max_input_vars 100000' > /etc/apache2/conf-available/p2s_maxinput.conf 2>/dev/null; a2enconf p2s_maxinput 2>/dev/null"
  REM 4) Apache restart
  docker exec $c sh -c "apachectl -k graceful 2>/dev/null || service apache2 graceful 2>/dev/null || kill -USR2 1 2>/dev/null"
  timeout /t 1 >nul
}
echo.
echo [dogrula] max_input_vars:
for /f "tokens=2" %%p in ('powershell -command "@{'5.4.45'='18101';'5.5.38'='18102';'5.6.40'='18103';'7.0.33'='18104';'7.1.33'='18105';'7.2.34'='18106';'7.3.33'='18107';'7.4.33'='18108';'8.0.30'='18109';'8.1.32'='18110';'8.2.34'='18111';'8.3.35'='18112';'8.4.26'='18113';'8.5.11'='18114'} | ForEach-Object { \$v=\$_; \$p=(\$_ -split '=')[1]; Write-Host (\$v + ' ' + (\$p -replace '\"','')) }"') do (
  echo   %%p
)
echo.
echo [hedef 18113 dogrudan]
curl -s --max-time 6 "http://127.0.0.1:18113/p2s_probe.php" 2>nul | findstr /i "max_input_vars"
echo.
echo ============================================
echo  Bitti. Mac'ten exploit'i calistir.
echo ============================================
endlocal
pause
