@echo off
setlocal enabledelayedexpansion

:: Quick installer for Driver Updater Tool
:: Auto-elevates and runs the main script
:: Version: 4.4

:: Set script directory (handles spaces in paths)
set "SCRIPT_DIR=%~dp0"

:: Check if we're already admin
net session >nul 2>&1
if %errorlevel% == 0 (
    :: Already admin, run the main script
    if exist "%SCRIPT_DIR%WindowsDriverUpdater_Ultimate.ps1" (
        powershell -ExecutionPolicy Bypass -File "%SCRIPT_DIR%WindowsDriverUpdater_Ultimate.ps1"
        exit /b %errorlevel%
    ) else (
        echo ERROR: WindowsDriverUpdater_Ultimate.ps1 not found!
        echo Expected location: "%SCRIPT_DIR%WindowsDriverUpdater_Ultimate.ps1"
        pause
        exit /b 1
    )
) else (
    :: Not admin, self-elevate with proper path quoting
    echo Requesting administrator privileges...
    powershell -Command "Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File ""%SCRIPT_DIR%WindowsDriverUpdater_Ultimate.ps1""' -Verb RunAs"
    if %errorlevel% neq 0 (
        echo ERROR: Failed to elevate privileges
        pause
        exit /b 1
    )
)
exit /b 0
