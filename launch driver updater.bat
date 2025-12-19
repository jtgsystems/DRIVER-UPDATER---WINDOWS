@echo off
setlocal enabledelayedexpansion

:: Windows Driver Updater Quick Launcher
:: Version: 4.3

:: Determine the full path to the companion .ps1 file
set "SCRIPT_DIR=%~dp0"
set "PS1File=%SCRIPT_DIR%WindowsDriverUpdater_Updated.ps1"

:: Check if PowerShell script exists
if not exist "%PS1File%" (
    echo ERROR: PowerShell script not found at:
    echo %PS1File%
    pause
    exit /b 1
)

:: Check if PowerShell is available
powershell -Command "Get-Host" >nul 2>&1
if errorlevel 1 (
    echo ERROR: PowerShell is not available or not in PATH
    pause
    exit /b 1
)

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process PowerShell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"\"%PS1File%\"\"' -Verb RunAs -Wait"
    if %errorlevel% neq 0 (
        echo ERROR: Failed to launch with administrative privileges
        pause
        exit /b 1
    )
) else (
    :: Already admin, run directly
    echo Launching Driver Updater...
    PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1File%"
    if %errorlevel% neq 0 (
        echo.
        echo Driver Updater completed with warnings or errors.
        pause
        exit /b %errorlevel%
    )
)

echo.
echo Driver Updater completed successfully.
pause
exit /b 0
