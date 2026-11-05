@echo off
setlocal
title Qwen3.8 27B Q4 - DFlash2 256K

cd /d C:\llama-dflash2

echo ==========================================
echo Qwen3.8 27B Q4_K_M
echo DFlash2: ACIK
echo MTP: KAPALI
echo TurboQuant: KAPALI
echo Context: 256K
echo KV Cache: Q4_0
echo ==========================================

set "SERVER=build\bin\Release\llama-server.exe"
set "MODEL=%USERPROFILE%\.ollama\models\blobs\sha256-98f6ebb527917a2541df8e667d51c3ec8a8bb135b44c606d40cc6ed924e89e52"
if not exist "%SERVER%" (
    echo HATA: llama-server.exe bulunamadi.
    pause
    exit /b 1
)

if not exist "%MODEL%" (
    echo HATA: Ana model bulunamadi.
    pause
    exit /b 1
)



"%SERVER%" ^
  -m "%MODEL%" ^
  --spec-type draft-mtp ^
  --spec-draft-n-max 16 ^
  -ngl 99 ^
  -c 262144 ^
  -ctk q4_0 ^
  -ctv q4_0 ^
  -fa on ^
  -np 1 ^
  --host 0.0.0.0 ^
  --port 9933

echo.
echo Sunucu kapandi. Hata mesajlarini kontrol et.
pause
endlocal
