@echo off
setlocal enabledelayedexpansion
title php2shell — memory_limit=8M (18113 only) — eness OOM calibration
echo ============================================
echo  memory_limit=8M on 18113 (eness OOM needs low memory_limit)
echo ============================================
echo.
docker info >nul 2>&1
if errorlevel 1 ( echo [HATA] Docker calismiyor. & exit /b 1 )

REM Find the container mapped to 18113
for /f "tokens=2" %%c in ('docker ps --format "{{.Names}} {{.Ports}}" ^| findstr "18113"') do (
  echo  Container: %%c
  set C=%%c
)
if not defined C ( echo [HATA] 18113 container bulunamadi. & exit /b 1 )

docker exec %C% sh -c "sed -i 's/^memory_limit.*/memory_limit = 8M/' /usr/local/etc/php/php.ini 2>/dev/null || echo 'memory_limit = 8M' >> /usr/local/etc/php/php.ini"
docker exec %C% sh -c "echo 'memory_limit = 8M' > /usr/local/etc/php/conf.d/99_p2s_memlimit.ini 2>/dev/null"
docker exec %C% sh -c "echo 'php_value memory_limit 8M' > /etc/apache2/conf-enabled/p2s_memlimit.conf 2>/dev/null; a2enconf p2s_memlimit 2>/dev/null"
docker exec %C% sh -c "apachectl -k graceful 2>/dev/null || service apache2 graceful 2>/dev/null"
timeout /t 2 >nul

echo.
echo [dogrula] memory_limit:
curl -s --max-time 6 "http://127.0.0.1:18113/p2s_probe.php" 2>nul | findstr /i "memory_limit"
echo.
echo ============================================
echo  Bitti. Mac'ten OOM + probe testini calistir.
echo ============================================
endlocal
pause
