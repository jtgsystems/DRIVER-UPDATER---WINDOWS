@echo off
:: SOTA 2026: Ultra-Fast Windows Driver Updater Launcher
:: Automatically detects and runs the optimized version

title Windows Driver Updater v5.0

:: Check for admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script requires Administrator privileges.
    echo Please right-click and select "Run as administrator"
    pause
    exit /b 1
)

:: Determine script location
set "SCRIPT_DIR=%~dp0"
set "OPTIMIZED_PS=%SCRIPT_DIR%WindowsDriverUpdater_Optimized.ps1"
set "LEGACY_PS=%SCRIPT_DIR%WindowsDriverUpdater_AutoStart.ps1"

:: Check for PowerShell
where powershell >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: PowerShell not found
    pause
    exit /b 1
)

:: Run optimized version if available, otherwise fall back
if exist "%OPTIMIZED_PS%" (
    echo Starting Windows Driver Updater v5.0 (SOTA 2026 Optimized)...
    powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%OPTIMIZED_PS%"
) else if exist "%LEGACY_PS%" (
    echo Starting Windows Driver Updater (Legacy Mode)...
    powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%LEGACY_PS%"
) else (
    echo ERROR: No driver updater script found
    echo Expected: WindowsDriverUpdater_Optimized.ps1
    pause
    exit /b 1
)

:: Pause on error
if %errorLevel% neq 0 (
    echo.
    echo Script completed with errors. Check the log file for details.
    pause
)

exit /b %errorLevel%
