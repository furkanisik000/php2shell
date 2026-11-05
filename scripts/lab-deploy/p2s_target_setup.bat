@echo off
setlocal enabledelayedexpansion
title php2shell target setup (PHP 8.4.26, native amd64)
echo ============================================
echo  php2shell target kurulumu
echo  PHP 8.4.26 (baseline) + index.php + native amd64
echo ============================================
echo.

REM --- 0) Docker calisiyor mu? ---
docker info >nul 2>&1
if errorlevel 1 (
    echo [HATA] Docker calismiyor. Docker Desktop'i acip tekrar dene.
    exit /b 1
)
echo [0/4] Docker OK
echo.

REM --- 1) image cek ---
echo [1/4] docker pull php:8.4.26-apache (native amd64)...
docker pull --platform linux/amd64 php:8.4.26-apache
if errorlevel 1 (
    echo [HATA] pull basarisiz.
    exit /b 1
)
echo.

REM --- 2) container calistir (port 18120) ---
echo [2/4] container calistir: p2s84  (host 18120 -> container 80)...
docker rm -f p2s84 2>nul
docker run -d --name p2s84 --restart unless-stopped -p 18120:80 php:8.4.26-apache
if errorlevel 1 (
    echo [HATA] container run basarisiz.
    exit /b 1
)
echo    basladi, 3 sn bekleniyor (apache warmup)...
timeout /t 3 >nul
echo.

REM --- 3) index.php koy (exploit hedef sayfasi) ---
echo [3/4] index.php'yi /var/www/html/ koy...
docker exec p2s84 sh -c "printf '%s' '<?php echo \"OK\n\"; ?>' > /var/www/html/index.php"
if errorlevel 1 (
    echo [UYARI] docker exec ile koyaemedim, docker cp dene...
    echo '<?php echo "OK"; ?>' > "%TEMP%\p2s_index.php"
    docker cp "%TEMP%\p2s_index.php" p2s84:/var/www/html/index.php
)
echo.

REM --- 4) dogrula ---
echo [4/4] dogrula (local + LAN)...
echo   - local : 
for /f %%a in ('curl -s --max-time 6 http://127.0.0.1:18120/index.php 2^>nul') do echo      %%a
echo   - LAN   : http://LAB_IP:18120/index.php
echo.
echo ============================================
echo  HAZIR: PHP 8.4.26 target (native amd64)
echo  URL   : http://LAB_IP:18120/index.php
echo  Offset: zif_system=0x465370  zval_ptr_dtor=0x65EB60
echo  Asistan (Mac) simdi exploit'i calistiracaktir.
echo ============================================
endlocal
pause
