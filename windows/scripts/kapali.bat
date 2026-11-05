
@echo off
cd /d C:\llama-dflash2

findstr /s /i /m "mtp multi_token_prediction" *.cpp *.h >nul 2>&1

if %errorlevel%==0 (
    echo MTP KODDA VAR
) else (
    echo MTP KODDA YOK
)

pause
