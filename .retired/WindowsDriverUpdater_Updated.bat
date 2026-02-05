@echo off
setlocal enabledelayedexpansion

:: Windows Driver Updater Batch Script
:: Enhanced version with error handling and logging

title Windows Driver Updater - Enhanced

:: Set console colors and window
color 0F
mode con: cols=120 lines=35

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Administrator privileges required!
    echo.
    echo Please right-click and select "Run as administrator"
    pause
    exit /b 1
)

:: Set script directory (handles spaces in path)
set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%WindowsDriverUpdater_Updated.ps1"

:: Check if PowerShell script exists
if not exist "%PS_SCRIPT%" (
    echo ERROR: PowerShell script not found!
    echo Expected location: "%PS_SCRIPT%"
    pause
    exit /b 1
)

:: Display header
cls
echo ========================================
echo    Windows Driver Updater - Enhanced
echo ========================================
echo.

:: Check PowerShell version
powershell -Command "$PSVersionTable.PSVersion.Major" >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: PowerShell not found or not accessible!
    pause
    exit /b 1
)

:: Main menu
:menu
cls
echo ========================================
echo    Windows Driver Updater - Enhanced
echo ========================================
echo.
echo Select an option:
echo.
echo [1] Check and install all driver updates
echo [2] Check and install with custom filters
echo [3] Silent installation (no prompts)
echo [4] Safe mode (restore point + backup)
echo [5] Advanced options
echo [6] View log file
echo [7] Exit
echo.
set /p choice=Enter your choice (1-7): 

if "%choice%"=="1" goto all_updates
if "%choice%"=="2" goto custom_filters
if "%choice%"=="3" goto silent_install
if "%choice%"=="4" goto safe_mode
if "%choice%"=="5" goto advanced_options
if "%choice%"=="6" goto view_log
if "%choice%"=="7" goto exit
goto menu

:all_updates
cls
echo ========================================
echo    Installing All Driver Updates
echo ========================================
echo.
echo Starting driver update process...
echo.
powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT%"
echo.
pause
goto menu

:custom_filters
cls
echo ========================================
echo    Custom Driver Update Filters
echo ========================================
echo.
set /p driver_filter=Enter driver filter keywords (comma-separated, or press Enter for all): 
set /p exclude_filter=Enter exclude keywords (comma-separated, or press Enter for none): 
echo.
echo Starting driver update with filters...
echo.
if "%driver_filter%"=="" (
    if "%exclude_filter%"=="" (
        powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT%"
    ) else (
        powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -ExcludeFilter "%exclude_filter%"
    )
) else (
    if "%exclude_filter%"=="" (
        powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -DriverFilter "%driver_filter%"
    ) else (
        powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -DriverFilter "%driver_filter%" -ExcludeFilter "%exclude_filter%"
    )
)
echo.
pause
goto menu

:silent_install
cls
echo ========================================
echo    Silent Driver Installation
echo ========================================
echo.
echo Running silent installation...
echo Check the log file for progress...
echo.
powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -Silent
echo.
pause
goto menu

:safe_mode
cls
echo ========================================
echo    Safe Mode - Backup and Restore Point
echo ========================================
echo.
echo Creating restore point and driver backup...
echo.
powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -CreateRestorePoint -SkipBackup:$false
echo.
pause
goto menu

:advanced_options
cls
echo ========================================
echo    Advanced Options
echo ========================================
echo.
echo [1] Limit number of updates
echo [2] Force installation (unsigned drivers)
echo [3] Skip backup for faster execution
echo [4] Custom log location
echo [5] Back to main menu
echo.
set /p adv_choice=Enter your choice (1-5): 

if "%adv_choice%"=="1" goto limit_updates
if "%adv_choice%"=="2" goto force_install
if "%adv_choice%"=="3" goto skip_backup
if "%adv_choice%"=="4" goto custom_log
if "%adv_choice%"=="5" goto menu
goto advanced_options

:limit_updates
cls
echo ========================================
echo    Limit Number of Updates
echo ========================================
echo.
set /p max_updates=Enter maximum number of updates to install (0 for all): 
echo.
echo Installing with limit of %max_updates% updates...
echo.
powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -MaxUpdates %max_updates%
echo.
pause
goto advanced_options

:force_install
cls
echo ========================================
echo    Force Installation Mode
echo ========================================
echo.
echo WARNING: This will install unsigned drivers!
echo Only use if you trust the driver source.
echo.
pause
powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -Force
echo.
pause
goto advanced_options

:skip_backup
cls
echo ========================================
echo    Skip Backup Mode
echo ========================================
echo.
echo WARNING: Skipping driver backup for faster execution!
echo No rollback will be available if issues occur.
echo.
pause
powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -SkipBackup
echo.
pause
goto advanced_options

:custom_log
cls
echo ========================================
echo    Custom Log Location
echo ========================================
echo.
set /p log_path=Enter full path for log file (e.g., C:\Logs\driver.log): 
echo.
echo Running with custom log location...
echo.
powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -LogPath "%log_path%"
echo.
pause
goto advanced_options

:view_log
cls
echo ========================================
echo    Driver Update Log
echo ========================================
echo.
if exist "%SCRIPT_DIR%DriverUpdaterLog.txt" (
    type "%SCRIPT_DIR%DriverUpdaterLog.txt"
) else (
    echo Log file not found. Run the updater first.
    echo Expected location: "%SCRIPT_DIR%DriverUpdaterLog.txt"
)
echo.
pause
goto menu

:exit
cls
echo ========================================
echo    Windows Driver Updater
echo ========================================
echo.
echo Thank you for using Windows Driver Updater!
echo.
echo Log file location: "%SCRIPT_DIR%DriverUpdaterLog.txt"
echo Backup location: "%SCRIPT_DIR%DriverBackups\"
echo.
pause
exit /b 0