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
    if exist "%SCRIPT_DIR%WindowsDriverUpdater_AutoStart.bat" (
        call "%SCRIPT_DIR%WindowsDriverUpdater_AutoStart.bat"
        exit /b %errorlevel%
    ) else (
        echo ERROR: WindowsDriverUpdater_AutoStart.bat not found!
        echo Expected location: "%SCRIPT_DIR%WindowsDriverUpdater_AutoStart.bat"
        pause
        exit /b 1
    )
) else (
    :: Not admin, self-elevate with proper path quoting
    echo Requesting administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%SCRIPT_DIR%WindowsDriverUpdater_AutoStart.bat\"\"' -Verb RunAs"
    if %errorlevel% neq 0 (
        echo ERROR: Failed to elevate privileges
        pause
        exit /b 1
    )
)
exit /b 0
