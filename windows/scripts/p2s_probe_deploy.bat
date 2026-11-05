@echo off
setlocal enabledelayedexpansion
title php2shell config probe — deploy p2s_probe.php to all 14 containers
echo ============================================
echo  php2shell config probe
echo  Hedefin GERCEK config'ini oku (memory_limit, post_max_size, glibc, Debian)
echo ============================================
echo.

REM --- 0) Docker calisiyor mu? ---
docker info >nul 2>&1
if errorlevel 1 (
    echo [HATA] Docker calismiyor.
    exit /b 1
)

REM --- probe php dosyasini hazirla ---
set "PROBE=%~dp0p2s_probe.php"
if not exist "%PROBE%" (
    echo [HATA] p2s_probe.php bulunamadi: %PROBE%
    exit /b 1
)
echo [0] probe dosyasi: %PROBE%
echo.

REM --- 1) hepsine cp ---
echo [1] 14 container'a p2s_probe.php koyuyorum...
docker ps -a --filter "name=p2s" --format "{{.Names}}" | ForEach-Object {
  docker cp "%PROBE%" $_":/var/www/html/p2s_probe.php" 2>nul
  echo   -> $_
}
echo.

REM --- 2) oku + goster ---
echo [2] Hedef config'leri (localhost + LAN):
echo ============================================
$map = @{
  "5.4.45"="18101"; "5.5.38"="18102"; "5.6.40"="18103";
  "7.0.33"="18104"; "7.1.33"="18105"; "7.2.34"="18106"; "7.3.33"="18107";
  "7.4.33"="18108"; "8.0.30"="18109"; "8.1.32"="18110"; "8.2.34"="18111";
  "8.3.35"="18112"; "8.4.26"="18113"; "8.5.11"="18114"
}
foreach ($v in ($map.Keys | Sort-Object)) {
  $port = $map[$v]
  Write-Host ""
  Write-Host "=== PHP $v  (port $port) ==="
  curl -s --max-time 8 "http://127.0.0.1:$port/p2s_probe.php" 2>$null
  if ($LASTEXITCODE -ne 0) { Write-Host "  [FAIL] port $port yanit vermedi" }
}
echo.
echo ============================================
echo  Bitti. Simdi Mac'ten de oku:
echo  curl http://192.168.8.123:18113/p2s_probe.php
echo ============================================
endlocal
pause
