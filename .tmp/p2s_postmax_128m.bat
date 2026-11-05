@echo off
setlocal enabledelayedexpansion
title php2shell — post_max_size=128M (Gemini fix) — 18113 only
echo ============================================
echo  post_max_size=128M + upload_max_filesize=64M on 18113
echo  memory_limit=8M KALIYOR (low, OOM icin)
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

REM Set post_max_size + upload_max_filesize HIGH, keep memory_limit LOW
docker exec %C% sh -c "printf 'post_max_size = 128M\nupload_max_filesize = 64M\n' > /usr/local/etc/php/conf.d/99_p2s_postmax.ini"
docker exec %C% sh -c "echo 'php_value post_max_size 128M' >> /etc/apache2/conf-enabled/p2s_memlimit.conf 2>/dev/null"
docker exec %C% sh -c "echo 'php_value upload_max_filesize 64M' >> /etc/apache2/conf-enabled/p2s_memlimit.conf 2>/dev/null"
docker exec %C% sh -c "apachectl -k graceful 2>/dev/null || service apache2 graceful 2>/dev/null"
timeout /t 2 >nul

echo.
echo [dogrula] config:
curl -s --max-time 6 "http://127.0.0.1:18113/p2s_probe.php" 2>nul | findstr /i "memory_limit post_max_size upload_max"
echo.
echo ============================================
echo  Bitti. Mac'ten Content-Length + chunked testini calistir.
echo ============================================
endlocal
pause
