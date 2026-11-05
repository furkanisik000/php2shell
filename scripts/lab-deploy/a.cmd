
@echo off
setlocal
title Gemma 4 Ollama Blob Inceleme

set "ROOT=%USERPROFILE%\.ollama\models"
set "MANIFEST=%ROOT%\manifests\registry.ollama.ai\library\gemma4\26b"

echo === Gemma 4 manifest ===
if not exist "%MANIFEST%" (
    echo Manifest bulunamadi: %MANIFEST%
    pause
    exit /b 1
)

type "%MANIFEST%"
echo.
echo === Blob dosyalari ===
for /f "tokens=2 delims=:" %%A in ('findstr /i "sha256" "%MANIFEST%"') do (
    set "HASH=%%A"
    call :SHOWBLOB
)
echo.
echo Inceleme tamamlandi. Dosyalar degistirilmedi.
pause
exit /b 0

:SHOWBLOB
set "HASH=%HASH: =%"
set "HASH=%HASH:"=%"
if exist "%ROOT%\blobs\%HASH%" (
    for %%F in ("%ROOT%\blobs\%HASH%") do (
        echo %%~zF bytes  %%~nxF
    )
)
exit /b
