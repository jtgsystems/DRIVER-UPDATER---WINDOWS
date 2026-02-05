@echo off
setlocal enabledelayedexpansion

:: Windows Driver Updater Auto-Start Launcher
:: Handles USB/Local execution with auto-startup registration

title Windows Driver Updater - Auto Start
color 0A

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo ========================================
    echo    ELEVATING TO ADMINISTRATOR
    echo ========================================
    echo.
    echo Requesting administrator privileges...
    
    :: Self-elevate to admin
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Detect if running from USB drive
set "SCRIPT_PATH=%~dp0"
set "IS_USB=0"

for /f "tokens=1,2" %%a in ('wmic logicaldisk get deviceid^,drivetype ^| findstr /r "^[A-Z]:"') do (
    if "%%b"=="2" (
        set "USB_DRIVE=%%a"
        if "!SCRIPT_PATH:~0,2!"=="!USB_DRIVE!" (
            set "IS_USB=1"
        )
    )
)

:: Set PowerShell script path
set "PS_SCRIPT=%SCRIPT_PATH%WindowsDriverUpdater_AutoStart.ps1"

:: Check if PowerShell script exists
if not exist "%PS_SCRIPT%" (
    echo.
    echo ERROR: PowerShell script not found!
    echo Expected: %PS_SCRIPT%
    echo.
    pause
    exit /b 1
)

:: Display header
cls
echo ========================================
echo    Windows Driver Updater Auto-Start
echo ========================================
echo.
echo Script Location: %SCRIPT_PATH%
if "%IS_USB%"=="1" (
    echo Running from: USB Drive
    echo.
    echo The script will be copied to local drive
    echo and configured for automatic startup.
) else (
    echo Running from: Local Drive
)
echo.
echo ========================================
echo.

:: Main menu
:menu
echo Select an option:
echo.
echo [1] Install and Configure Auto-Start
echo [2] Check for Updates Only
echo [3] Remove from Startup
echo [4] View Status
echo [5] Exit
echo.
set /p choice=Enter your choice (1-5): 

if "%choice%"=="1" goto install_auto
if "%choice%"=="2" goto check_only
if "%choice%"=="3" goto remove_startup
if "%choice%"=="4" goto view_status
if "%choice%"=="5" goto exit
goto menu

:install_auto
cls
echo ========================================
echo    Installing Driver Updater
echo ========================================
echo.
echo This will:
echo  1. Check for driver updates
echo  2. Install available updates
echo  3. Add to Windows startup
echo  4. Auto-remove when complete
echo.
echo Starting installation...
echo.

powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT%"

echo.
echo ========================================
echo Installation process started.
echo The updater will run automatically at startup
echo and remove itself when all drivers are installed.
echo.
pause
goto menu

:check_only
cls
echo ========================================
echo    Checking for Driver Updates
echo ========================================
echo.

powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -CheckOnly

echo.
pause
goto menu

:remove_startup
cls
echo ========================================
echo    Remove from Startup
echo ========================================
echo.
echo Removing driver updater from startup...
echo.

powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -RemoveFromStartup

echo.
echo Removal complete.
pause
goto menu

:view_status
cls
echo ========================================
echo    Driver Updater Status
echo ========================================
echo.

:: Check if state file exists
set "STATE_FILE=%ProgramData%\DriverUpdater\DriverUpdater.state"
if exist "%STATE_FILE%" (
    echo Current State:
    type "%STATE_FILE%"
    echo.
) else (
    echo No state file found. Updater has not been run yet.
)

echo.
echo ========================================
echo Log File Contents (last 20 lines):
echo ========================================

set "LOG_FILE=%ProgramData%\DriverUpdater\DriverUpdater_AutoStart.log"
if exist "%LOG_FILE%" (
    powershell -Command "Get-Content '%LOG_FILE%' -Tail 20"
) else (
    set "LOG_FILE=%SCRIPT_PATH%DriverUpdater_AutoStart.log"
    if exist "%LOG_FILE%" (
        powershell -Command "Get-Content '%LOG_FILE%' -Tail 20"
    ) else (
        echo No log file found.
    )
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
if "%IS_USB%"=="1" (
    echo Note: You can safely remove the USB drive.
    echo The updater will continue to run from the local copy.
)
echo.
pause
exit /b 0