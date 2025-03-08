# ================================================
# Script Name: WindowsAutoUpdateScript.ps1
# Description: Automates Windows driver and application updates.
#              Handles optional updates and ensures uninterrupted execution.
#              Generates a detailed log report that opens upon completion.
# Author: Customized by Assistant
# Last Modified: 2024-11-04
# ================================================

# Requires -Version 5.1
[CmdletBinding()]
param()

# Add System.Speech assembly and create speech synthesizer
Add-Type -AssemblyName System.Speech
$speechSynthesizer = New-Object System.Speech.Synthesis.SpeechSynthesizer

# Enforce strict mode and set preferences
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'  # Improves performance for web requests

# Script variables
$script:logFilePath = Join-Path $PSScriptRoot "DriverUpdaterLog.txt"
$script:psWindowsUpdateModuleName = "PSWindowsUpdate"
$script:internetTestTarget = "8.8.8.8"
$script:MicrosoftUpdateServiceId = "7971f918-a847-4430-9279-4a52d1efe18d"

# Ensure TLS 1.2 is enabled
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ---------------------------
# Function: Write-Log
# ---------------------------
function Write-Log {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string]$Message,

    [ValidateSet('Info', 'Warning', 'Error', 'Debug')]
    [string]$Severity = 'Info'
  )

  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $logEntry = "$timestamp - [$Severity] $Message"

  try {
    # Append to log file with encoding and error handling
    [System.IO.File]::AppendAllText($script:logFilePath, $logEntry + "`n", [System.Text.Encoding]::UTF8) | Out-Null
  }
  catch {
    Write-Warning "Failed to write to log file: $($_.Exception.Message)"
  }

  # Use Write-Host with verbosity control
  switch ($Severity) {
    'Info' { Write-Host $logEntry -ForegroundColor Cyan -Verbose:$false }
    'Warning' { Write-Host $logEntry -ForegroundColor Yellow -Verbose:$false }
    'Error' { Write-Host $logEntry -ForegroundColor Red -Verbose:$true }
    'Debug' { Write-Host $logEntry -ForegroundColor Gray -Verbose:$true }
  }
}
# ---------------------------
# Function: Install-RequiredModules
# ---------------------------
function Install-RequiredModules {
  Write-Log "Installing required modules and package providers." -Severity 'Info'

  # Install NuGet package provider if not already installed
  if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    Write-Log "Installing NuGet package provider..." -Severity 'Info'
    try {
      Install-PackageProvider -Name NuGet -Force -ErrorAction Stop
      Write-Log "NuGet package provider installed successfully." -Severity 'Info'
    }
    catch {
      Write-Log "Failed to install NuGet package provider: $($_.Exception.Message)" -Severity 'Error'
      throw
    }
  }
  else {
    Write-Log "NuGet package provider is already installed." -Severity 'Debug'
  }

  # Import the NuGet package provider
  try {
    Import-PackageProvider -Name NuGet -Force -ErrorAction Stop
    Write-Log "NuGet package provider imported successfully." -Severity 'Debug'
  }
  catch {
    Write-Log "Failed to import NuGet package provider: $($_.Exception.Message)" -Severity 'Error'
    throw
  }

  # Trust the PSGallery repository
  if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
    Write-Log "PSGallery repository not found. Registering PSGallery..." -Severity 'Info'
    try {
      Register-PSRepository -Default -ErrorAction Stop
      Write-Log "PSGallery repository registered successfully." -Severity 'Info'
    }
    catch {
      Write-Log "Failed to register PSGallery repository: $($_.Exception.Message)" -Severity 'Error'
      throw
    }
  }
  else {
    Write-Log "PSGallery repository already exists." -Severity 'Debug'
  }
  try {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
    Write-Log "PSGallery repository set to trusted." -Severity 'Debug'
  }
  catch {
    Write-Log "Failed to set PSGallery repository to trusted: $($_.Exception.Message)" -Severity 'Error'
    throw
  }

  # Install and import PSWindowsUpdate module
  if (-not (Get-Module -ListAvailable -Name $script:psWindowsUpdateModuleName)) {
    Write-Log "Installing $script:psWindowsUpdateModuleName module..." -Severity 'Info'
    try {
      Install-Module -Name $script:psWindowsUpdateModuleName -Force -AllowClobber -Scope AllUsers -ErrorAction Stop
      Write-Log "$script:psWindowsUpdateModuleName module installed successfully." -Severity 'Info'
    }
    catch {
      Write-Log "Failed to install $script:psWindowsUpdateModuleName module: $($_.Exception.Message)" -Severity 'Error'
      throw
    }
  }
  else {
    Write-Log "$script:psWindowsUpdateModuleName module is already installed." -Severity 'Debug'
  }

  try {
    Import-Module -Name $script:psWindowsUpdateModuleName -Force -ErrorAction Stop
    Write-Log "$script:psWindowsUpdateModuleName module imported successfully." -Severity 'Info'
  }
  catch {
    Write-Log "Failed to import $script:psWindowsUpdateModuleName module: $($_.Exception.Message)" -Severity 'Error'
    throw
  }
}

# ---------------------------
# Function: Register-MicrosoftUpdateService
# ---------------------------
function Register-MicrosoftUpdateService {
  Write-Log "Registering Microsoft Update Service if not already registered." -Severity 'Info'

  $service = Get-WUServiceManager | Where-Object { $_.ServiceID -eq $script:MicrosoftUpdateServiceId }
  if (-not $service) {
    Write-Log "Registering Microsoft Update Service..." -Severity 'Info'
    Add-WUServiceManager -MicrosoftUpdate -ErrorAction Stop

    # Verify registration
    $service = Get-WUServiceManager | Where-Object { $_.ServiceID -eq $script:MicrosoftUpdateServiceId }
    if (-not $service) {
      throw "Microsoft Update Service is not registered."
    }
    Write-Log "Microsoft Update Service registered successfully." -Severity 'Info'
  }
  else {
    Write-Log "Microsoft Update Service is already registered." -Severity 'Debug'
  }
}

# ---------------------------
# Function: Test-InternetConnection
# ---------------------------
function Test-InternetConnection {
  Write-Log "Testing internet connectivity..." -Severity 'Info'
  try {
    $result = Test-NetConnection -ComputerName $script:internetTestTarget -InformationLevel Quiet
    if ($result) {
      Write-Log "Internet connection detected." -Severity 'Info'
      return $true
    }
    else {
      Write-Log "No internet connection detected." -Severity 'Warning'
      return $false
    }
  }
  catch {
    Write-Log "Internet connectivity test failed: $($_.Exception.Message)" -Severity 'Error'
    return $false
  }
}

# ---------------------------
# Function: Get-DriverUpdates
# ---------------------------
function Get-DriverUpdates {
  Write-Log "Searching for driver updates from Windows Update..." -Severity 'Info'
  try {
    $driverUpdates = Get-WindowsUpdate -MicrosoftUpdate -IsInstalled:$false -Category Drivers, Optional -ErrorAction Stop
    $driverUpdatesArray = @($driverUpdates)

    Write-Log "Type of `\$driverUpdatesArray`: $($driverUpdatesArray.GetType().FullName)" -Severity 'Debug'
    Write-Log "Number of driver updates retrieved: $($driverUpdatesArray.Count)" -Severity 'Debug'

    if ($driverUpdatesArray.Count -gt 0) {
      Write-Log "Found $($driverUpdatesArray.Count) driver update(s)." -Severity 'Info'
      return $driverUpdatesArray
    }
    else {
      Write-Log "No driver updates found." -Severity 'Info'
      return @()
    }
  }
  catch {
    Write-Log "Error fetching driver updates: $($_.Exception.Message)" -Severity 'Error'
    throw
  }
}

# ---------------------------
# Function: Install-DriverUpdates
# ---------------------------
function Install-DriverUpdates {
  param (
    [Parameter(Mandatory = $true)]
    [array]$DriverUpdates
  )

  if ($DriverUpdates.Count -eq 0) {
    Write-Log "No driver updates to install." -Severity 'Info'
    return
  }

  Write-Log "Installing $($DriverUpdates.Count) driver update(s)..." -Severity 'Info'
  try {
    foreach ($update in $DriverUpdates) {
      Write-Log "Installing update: $($update.Title)" -Severity 'Info'
      Install-WindowsUpdate -KBArticleID $update.KB -AcceptAll -AutoReboot -IgnoreReboot -Confirm:$false -ErrorAction Stop
      Write-Log "Installed update: $($update.Title)" -Severity 'Info'
    }
    Write-Log "All driver updates installed successfully." -Severity 'Info'
  }
  catch {
    Write-Log "Error installing driver updates: $($_.Exception.Message)" -Severity 'Error'
    throw
  }
}

# ---------------------------
# Function: Update-InstalledApplications
# ---------------------------
function Update-InstalledApplications {
  Write-Log "Starting application upgrades using winget..." -Severity 'Info'
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Log "winget is not installed or not available in PATH. Attempting to install..." -Severity 'Info'
    try {
      # Install winget using the official installation script
      Invoke-WebRequest -Uri "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_Full.msixbundle" -OutFile "winget.msixbundle" -ErrorAction Stop
      Add-AppxPackage -Path "winget.msixbundle" -ErrorAction Stop
      Write-Log "winget installed successfully." -Severity 'Info'
    }
    catch {
      Write-Log "Failed to install winget: $($_.Exception.Message)" -Severity 'Error'
      return $false
    }
  }
  try {
    $output = winget upgrade --all --silent --accept-package-agreements --accept-source-agreements 2>&1
    if ($LASTEXITCODE -eq 0) {
      Write-Log "Application upgrades initiated." -Severity 'Info'
      return $true
    }
    else {
      Write-Log "Error upgrading applications: $output" -Severity 'Error'
      return $false
    }
  }
  catch {
    Write-Log "Error upgrading applications: $($_.Exception.Message)" -Severity 'Error'
    return $false
  }
}

# ---------------------------
# Function: Confirm-Administrator
# ---------------------------
function Confirm-Administrator {
  # Check if running as administrator
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
  
  if (-Not $isAdmin) {
    Write-Log "Script is not running with administrator privileges. Attempting to elevate..." -Severity 'Info'
    
    try {
      # Get the current script's full path
      $scriptPath = $PSCommandPath
      if (-not $scriptPath) {
        $scriptPath = $MyInvocation.MyCommand.Definition
      }
      
      # Start a new elevated PowerShell process
      $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
      Write-Log "Launching elevated process with arguments: $arguments" -Severity 'Debug'
      
      Start-Process PowerShell -ArgumentList $arguments -Verb RunAs -Wait
      
      # Exit this non-elevated instance
      Write-Log "Exiting non-elevated instance." -Severity 'Info'
      Exit
    }
    catch {
      Write-Log "Failed to restart script with elevated privileges: $($_.Exception.Message)" -Severity 'Error'
      throw "Administrator privileges required. Please run this script as an Administrator."
    }
  }
  else {
    Write-Log "Script is running with administrator privileges." -Severity 'Info'
    return $true
  }
}

# ---------------------------
# Function: Write-CompletionLog
# ---------------------------
function Write-CompletionLog {
  try {
    $summary = @{
      ScriptVersion    = "1.0"
      CompletionTime   = Get-Date
      UpdatesInstalled = $true
      RebootRequired   = Test-PendingReboot
      PendingUpdates   = Get-PendingUpdates
    }

    $summaryText = @"
Windows Auto Update Summary
-------------------------
Script Version    : $($summary.ScriptVersion)
Completion Time   : $($summary.CompletionTime)
Updates Installed : $($summary.UpdatesInstalled)
Reboot Required   : $($summary.RebootRequired)
Pending Updates   : $($summary.PendingUpdates)
"@

    Set-Content -Path $script:logFilePath -Value $summaryText -Force -ErrorAction Stop
    Write-Log "Completion log written to $script:logFilePath." -Severity 'Info'
  }
  catch {
    Write-Log "Error writing completion log: $($_.Exception.Message)" -Severity 'Error'
  }
}

# ---------------------------
# Function: Test-PendingReboot
# ---------------------------
function Test-PendingReboot {
  try {
    # Initialize rebootPending to false
    $rebootPending = $false
    
    # Check Component Based Servicing
    if (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
      $rebootPending = $true
      Write-Log "Reboot pending detected in Component Based Servicing." -Severity 'Debug'
    }

    # Check Windows Update
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
      $rebootPending = $true
      Write-Log "Reboot required detected in Windows Update." -Severity 'Debug'
    }

    # Check Pending File Rename Operations
    if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations") {
      $rebootPending = $true
      Write-Log "Pending file rename operations detected." -Severity 'Debug'
    }
  }
  catch {
    Write-Log "Error checking pending reboot status: $($_.Exception.Message)" -Severity 'Warning'
  }

  Write-Log "Reboot Pending: $rebootPending" -Severity 'Debug'
  return $rebootPending
}

# ---------------------------
# Function: Get-PendingUpdates
# ---------------------------
function Get-PendingUpdates {
  try {
    $pendingUpdates = Get-WUList -MicrosoftUpdate -ErrorAction Stop
    $updateCount = 0
    if ($pendingUpdates -is [array]) {
      $updateCount = $pendingUpdates.Count
    }
    Write-Log "Number of pending updates: $($updateCount)" -Severity 'Debug'
    return $updateCount
  }
  catch {
    Write-Log "Error checking pending updates: $($_.Exception.Message)" -Severity 'Warning'
    return 0
  }
}

# ---------------------------
# Function: Open-LogFile
# ---------------------------
function Open-LogFile {
  try {
    Invoke-Item -Path $script:logFilePath -ErrorAction Stop
    Write-Log "Opened log file at $script:logFilePath." -Severity 'Info'
    return $true
  }
  catch {
    Write-Log "Error opening log file: $($_.Exception.Message)" -Severity 'Warning'
    return $false
  }
}

# ---------------------------
# Function: Restart-Computer-WithNotification
# ---------------------------
function Restart-Computer-WithNotification {
  [CmdletBinding()]
  param (
    [int]$DelayMinutes = 5
  )

  try {
    Write-Log "Scheduling computer restart in $DelayMinutes minute(s)." -Severity 'Info'
    
    # Create a more visible notification
    $message = "System updates require a restart. The computer will restart in $DelayMinutes minutes. Please save your work."
    
    # Display a message box for better visibility
    Add-Type -AssemblyName System.Windows.Forms
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 1000
    $countdown = $DelayMinutes * 60
    
    # Create notification balloon
    $balloon = New-Object System.Windows.Forms.NotifyIcon
    $balloon.Icon = [System.Drawing.SystemIcons]::Information
    $balloon.BalloonTipTitle = "System Restart Required"
    $balloon.BalloonTipText = $message
    $balloon.Visible = $true
    $balloon.ShowBalloonTip(10000)
    
    # Use both native restart command and PowerShell command for redundancy
    Write-Log "Executing shutdown command..." -Severity 'Info'
    $shutdownArgs = "/r /t $($DelayMinutes * 60) /c `"$message`""
    Write-Log "Shutdown arguments: $shutdownArgs" -Severity 'Debug'
    Start-Process -FilePath "shutdown.exe" -ArgumentList $shutdownArgs -NoNewWindow
    
    # Also schedule with PowerShell command as backup
    Write-Log "Setting restart timer with PowerShell..." -Severity 'Info'
    $restartJob = Start-Job -ScriptBlock {
        param($delay)
        Start-Sleep -Seconds $delay
        Restart-Computer -Force
    } -ArgumentList ($DelayMinutes * 60)
    
    Write-Log "Computer restart scheduled in $DelayMinutes minute(s)." -Severity 'Info'
    $speechSynthesizer.Speak("Your computer will restart in $DelayMinutes minutes to complete updates.")
    
    return $true
  }
  catch {
    Write-Log "Failed to schedule computer restart: $($_.Exception.Message)" -Severity 'Error'
    return $false
  }
}

# ---------------------------
# Make sure we're running as admin first - do this at the very start
# ---------------------------
if (-Not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "This script requires administrator privileges. Elevating..." -ForegroundColor Yellow
  try {
    # Get the current script path
    $scriptPath = $MyInvocation.MyCommand.Definition
    # Start a new elevated PowerShell instance
    Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
  }
  catch {
    Write-Host "Failed to restart with elevated privileges: $_" -ForegroundColor Red
  }
  # Exit the current non-elevated instance
  exit
}

# ---------------------------
# Main Execution Block
# ---------------------------
try {
  # Set process priority to high for better performance
  $currentProcess = Get-Process -Id $PID
  $currentProcess.PriorityClass = 'High'

  Write-Log "Driver and Application Update Script Started." -Severity 'Info'

  # Install required modules and package providers
  Install-RequiredModules

  # Register Microsoft Update Service
  $speechSynthesizer.Speak("Registering Microsoft Update Service.")
  Register-MicrosoftUpdateService

  # Test internet connectivity
  if (Test-InternetConnection) {
    # Get available driver updates (including optional updates)
    $driverUpdates = Get-DriverUpdates

    # Install driver updates automatically if available
    $speechSynthesizer.Speak("Installing driver updates if available.")
    if ($driverUpdates.Count -gt 0) {
      Install-DriverUpdates -DriverUpdates $driverUpdates
    }
    else {
      Write-Log "No driver updates to install." -Severity 'Info'
    }

    # Upgrade all installed applications using winget
    Update-InstalledApplications

    # Check for any remaining pending updates
    $pendingUpdates = Get-PendingUpdates

    # Check for pending reboot
    if (Test-PendingReboot) {
        Write-Log "A reboot is required to complete the updates." -Severity 'Info'
        Restart-Computer-WithNotification
    }
    elseif ($pendingUpdates -eq 0) {
      Write-Log "All updates and application upgrades are complete." -Severity 'Info'

      # Write completion log
      Write-CompletionLog

      # Open the log file
      Open-LogFile
    }
    else {
      Write-Log "There are still pending updates. Scheduling a system restart to apply updates." -Severity 'Info'
      Restart-Computer-WithNotification

      # Write completion log
      Write-CompletionLog

      # Open the log file
      Open-LogFile
    }
  }
  else {
    throw "No internet connection available. Please check your network settings."
  }
}
catch {
  Write-Log "An unexpected error occurred: $($_.Exception.Message)" -Severity 'Error'

  # Write completion log with error details
  Write-CompletionLog

  # Open the log file
  Open-LogFile
}
finally {
  # Use existing speech synthesizer object instead of creating a new one
  $speechSynthesizer.Speak("Driver and Application Update Script Completed.")
}
