@echo off
setlocal enabledelayedexpansion
title php2shell — max_children=1 (single worker) — 18113
echo ============================================
echo  max_children=1 (single worker) on 18113
echo  OOM + leak read AYNI worker'a isabet etsin
echo ============================================
echo.
docker info >nul 2>&1
if errorlevel 1 ( echo [HATA] Docker calismiyor. & exit /b 1 )

for /f "tokens=2" %%c in ('docker ps --format "{{.Names}} {{.Ports}}" ^| findstr "18113"') do (
  set C=%%c
)
if not defined C ( echo [HATA] 18113 container bulunamadi. & exit /b 1 )
echo  Container: %C%

REM Set max_children=1 + StartServers=1 + MinSpareServers=1
docker exec %C% sh -c "sed -i 's/^<IfModule .*prefork.*/&/' /etc/apache2/mods-available/mpm_prefork.conf"
docker exec %C% sh -c "sed -i 's/MaxChildren.*/MaxChildren 1/' /etc/apache2/mods-available/mpm_prefork.conf"
docker exec %C% sh -c "sed -i 's/StartServers.*/StartServers 1/' /etc/apache2/mods-available/mpm_prefork.conf"
docker exec %C% sh -c "sed -i 's/MinSpareServers.*/MinSpareServers 1/' /etc/apache2/mods-available/mpm_prefork.conf"
docker exec %C% sh -c "sed -i 's/MaxSpareServers.*/MaxSpareServers 1/' /etc/apache2/mods-available/mpm_prefork.conf"
docker exec %C% sh -c "apachectl -k graceful 2>/dev/null || service apache2 graceful 2>/dev/null"
timeout /t 3 >nul

echo.
echo [dogrula] worker sayisi:
docker exec %C% sh -c "ps aux | grep -c apache2" 2>nul
echo.
echo ============================================
echo  Bitti. Mac'ten C concurrent testini calistir.
echo ============================================
endlocal
pause
