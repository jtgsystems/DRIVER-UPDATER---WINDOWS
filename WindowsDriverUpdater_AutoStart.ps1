#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Self-Installing Windows Driver and Update Tool with Auto-Startup and Self-Removal
.DESCRIPTION
    Automatically installs Windows updates and drivers on new systems, adds itself to startup,
    and removes itself when no more applicable updates are available. Feature upgrades
    (e.g., Windows 10 to Windows 11) are excluded.
.NOTES
    Version: 4.3
    Last Updated: 2025-12-19
    Requires: Windows PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param (
    [switch]$RemoveFromStartup,
    [switch]$CheckOnly,
    [string]$LogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'Continue'
$script:SkipFinalLog = $false

#region Configuration
$script:Config = @{
    ScriptName = "WindowsDriverUpdater_AutoStart"
    StartupRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    StartupTaskName = "DriverUpdaterAutoStart"
    LogFileName = "DriverUpdater_AutoStart.log"
    StateFile = "DriverUpdater.state"
    MaxRetries = 3
    RetryDelaySeconds = 5
    ModuleName = "PSWindowsUpdate"
    MSUpdateServiceId = "7971f918-a847-4430-9279-4a52d1efe18d"
    UpdateCategories = @(
        "Drivers",
        "CriticalUpdates",
        "SecurityUpdates",
        "UpdateRollups",
        "Updates"
    )
    ExcludedTitlePatterns = @(
        "*Feature update to Windows*",
        "*Upgrade to Windows*",
        "*Windows 11*"
    )
}

# Determine script location (USB or local)
$script:ScriptPath = $MyInvocation.MyCommand.Path
$script:ScriptDir = Split-Path -Parent $script:ScriptPath
$script:IsUSB = $false

# Check if running from USB drive (using CIM instead of deprecated WMI)
$drive = (Get-Item $script:ScriptPath).PSDrive
if ($drive) {
    try {
        $driveInfo = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$($drive.Name):'" -ErrorAction SilentlyContinue
        if ($driveInfo -and $driveInfo.DriveType -eq 2) {
            $script:IsUSB = $true
        }
    }
    catch {
        # Fallback: assume local if CIM query fails
        $script:IsUSB = $false
    }
}

# Set working directory (use ProgramData for reliable write access)
$script:WorkingDir = "$env:ProgramData\DriverUpdater"
if (-not (Test-Path $script:WorkingDir)) {
    New-Item -Path $script:WorkingDir -ItemType Directory -Force | Out-Null
}

# Set log path
if ($LogPath) {
    $script:LogPath = $LogPath
} else {
    $script:LogPath = Join-Path $script:WorkingDir $script:Config.LogFileName
}

$script:StateFilePath = Join-Path $script:WorkingDir $script:Config.StateFile
#endregion

#region Logging Functions
function Write-Log {
    param (
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Severity = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - [$Severity] $Message"
    
    try {
        $logDir = Split-Path -Parent $script:LogPath
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        Add-Content -Path $script:LogPath -Value $logEntry -ErrorAction SilentlyContinue
    } catch {
        # Fallback to event log if file write fails
        Write-EventLog -LogName Application -Source "DriverUpdater" -EventID 1000 -EntryType Information -Message $logEntry -ErrorAction SilentlyContinue
    }
    
    # Console output
    $color = switch ($Severity) {
        'Info' { 'Cyan' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        'Success' { 'Green' }
    }
    Write-Host $logEntry -ForegroundColor $color
}
#endregion

#region State Management
function Get-UpdaterState {
    if (Test-Path $script:StateFilePath) {
        try {
            return Get-Content $script:StateFilePath | ConvertFrom-Json
        } catch {
            return @{
                InstallCount = 0
                LastRun = $null
                ConsecutiveNoUpdates = 0
                IsComplete = $false
            }
        }
    }
    return @{
        InstallCount = 0
        LastRun = $null
        ConsecutiveNoUpdates = 0
        IsComplete = $false
    }
}

function Set-UpdaterState {
    param($State)
    $stateDir = Split-Path -Parent $script:StateFilePath
    if (-not (Test-Path $stateDir)) {
        New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
    }
    $State | ConvertTo-Json | Set-Content $script:StateFilePath -Force
}
#endregion

#region Startup Management
function Add-ToStartup {
    <#
    .SYNOPSIS
        Registers the script to run at Windows startup.
    .DESCRIPTION
        Uses both Registry Run key and Scheduled Task for reliability.
    #>
    [CmdletBinding()]
    param()

    Write-Log "Adding script to Windows startup..." -Severity Info

    try {
        if ($script:IsUSB) {
            # Copy script from USB to local directory
            $localScriptPath = Join-Path $script:WorkingDir "$($script:Config.ScriptName).ps1"
            Copy-Item -Path $script:ScriptPath -Destination $localScriptPath -Force
            $execPath = $localScriptPath
        }
        else {
            $execPath = $script:ScriptPath
        }

        # Validate the path exists and is a PowerShell script
        if (-not (Test-Path $execPath) -or -not $execPath.EndsWith('.ps1')) {
            throw "Invalid script path: $execPath"
        }

        # Method 1: Registry Run key (escaped path for security)
        $escapedPath = $execPath -replace '"', '\"'
        $regCommand = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$escapedPath`""
        Set-ItemProperty -Path $script:Config.StartupRegPath -Name $script:Config.StartupTaskName -Value $regCommand -Force

        # Method 2: Scheduled Task (backup method)
        $taskExists = Get-ScheduledTask -TaskName $script:Config.StartupTaskName -ErrorAction SilentlyContinue
        if (-not $taskExists) {
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$escapedPath`""
            $trigger = New-ScheduledTaskTrigger -AtStartup
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

            Register-ScheduledTask -TaskName $script:Config.StartupTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        }

        Write-Log "Successfully added to startup (Registry and Task Scheduler)" -Severity Success
        return $true
    }
    catch {
        Write-Log "Failed to add to startup: $($_.Exception.Message)" -Severity Error
        return $false
    }
}

function Remove-FromStartup {
    Write-Log "Removing script from Windows startup..." -Severity Info
    
    try {
        # Remove from registry
        Remove-ItemProperty -Path $script:Config.StartupRegPath -Name $script:Config.StartupTaskName -ErrorAction SilentlyContinue
        
        # Remove scheduled task
        Unregister-ScheduledTask -TaskName $script:Config.StartupTaskName -Confirm:$false -ErrorAction SilentlyContinue
        
        Write-Log "Successfully removed from startup" -Severity Success
        return $true
    } catch {
        Write-Log "Failed to remove from startup: $($_.Exception.Message)" -Severity Error
        return $false
    }
}

function Remove-SelfAndCleanup {
    <#
    .SYNOPSIS
        Removes the script from startup and cleans up files.
    .DESCRIPTION
        Safely removes all traces of the updater after completion.
    #>
    [CmdletBinding()]
    param()

    Write-Log "Performing self-removal and cleanup..." -Severity Info

    try {
        # Remove from startup first
        Remove-FromStartup

        # Delete state file
        if (Test-Path $script:StateFilePath) {
            Remove-Item $script:StateFilePath -Force -ErrorAction SilentlyContinue
        }

        # Clean up working directory using scheduled task
        # This is more secure than creating temp scripts
        if (Test-Path $script:WorkingDir) {
            $cleanupTaskName = "DriverUpdaterCleanup_$(Get-Random)"
            $cleanupAction = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c timeout /t 10 /nobreak >nul && rd /s /q `"$($script:WorkingDir)`""
            $cleanupTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
            $cleanupSettings = New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter (New-TimeSpan -Minutes 5)

            Register-ScheduledTask -TaskName $cleanupTaskName -Action $cleanupAction -Trigger $cleanupTrigger -Settings $cleanupSettings -Force | Out-Null
            Write-Log "Scheduled cleanup task: $cleanupTaskName" -Severity Info
        }

        Write-Log "Cleanup completed. Script will exit." -Severity Success
        return $true
    }
    catch {
        Write-Log "Cleanup failed: $($_.Exception.Message)" -Severity Error
        return $false
    }
}
#endregion

#region Update Functions
function Install-RequiredModules {
    Write-Log "Checking for required modules..." -Severity Info
    
    try {
        # Ensure modern TLS for module downloads
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            if ([Enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') {
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13
            }
        }
        catch {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }

        # Start Windows Update service if needed
        $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        if ($wuService -and $wuService.Status -ne "Running") {
            Start-Service -Name "wuauserv" -ErrorAction Stop
        }
        
        # Install NuGet provider
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -Force -MinimumVersion 2.8.5.201 | Out-Null
        }
        
        # Trust PSGallery
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        
        # Install PSWindowsUpdate module
        if (-not (Get-Module -ListAvailable -Name $script:Config.ModuleName)) {
            Install-Module -Name $script:Config.ModuleName -Force -AllowClobber -Scope AllUsers
        }
        
        Import-Module -Name $script:Config.ModuleName -Force
        Write-Log "Modules installed successfully" -Severity Success
        return $true
    } catch {
        Write-Log "Module installation failed: $($_.Exception.Message)" -Severity Error
        return $false
    }
}

function Get-AvailableUpdates {
    Write-Log "Checking for available Windows updates and drivers..." -Severity Info
    
    try {
        # Register Microsoft Update service
        $service = Get-WUServiceManager | Where-Object { $_.ServiceID -eq $script:Config.MSUpdateServiceId }
        if (-not $service) {
            Add-WUServiceManager -MicrosoftUpdate -ErrorAction Stop
        }
        
        # Get Windows updates and drivers, excluding upgrades
        $updates = Get-WindowsUpdate -MicrosoftUpdate -IsInstalled:$false -Category $script:Config.UpdateCategories -NotCategory "Upgrades" -ErrorAction Stop
        
        # Filter out preview/beta updates
        $validUpdates = @($updates | Where-Object { 
            $_.Title -notlike "*Preview*" -and 
            $_.Title -notlike "*Beta*"
        })

        # Exclude feature upgrades by title pattern as a safety net
        if ($script:Config.ExcludedTitlePatterns.Count -gt 0) {
            foreach ($pattern in $script:Config.ExcludedTitlePatterns) {
                $validUpdates = @($validUpdates | Where-Object { $_.Title -notlike $pattern })
            }
        }
        
        Write-Log "Found $($validUpdates.Count) updates" -Severity Info
        return $validUpdates
    } catch {
        Write-Log "Failed to check for updates: $($_.Exception.Message)" -Severity Error
        return @()
    }
}

function Install-Updates {
    param($Updates)
    
    if ($Updates.Count -eq 0) {
        Write-Log "No updates to install" -Severity Info
        return 0
    }
    
    Write-Log "Installing $($Updates.Count) updates..." -Severity Info
    $installed = 0
    
    foreach ($update in $Updates) {
        try {
            Write-Log "Installing: $($update.Title)" -Severity Info
            $update | Install-WindowsUpdate -AcceptAll -AutoReboot:$false -IgnoreReboot -ErrorAction Stop
            $installed++
            Write-Log "Successfully installed: $($update.Title)" -Severity Success
        } catch {
            Write-Log "Failed to install $($update.Title): $($_.Exception.Message)" -Severity Error
        }
    }
    
    return $installed
}
#endregion

#region Main Execution
try {
    $separator = [string]::new('=', 60)
    Write-Log $separator -Severity Info
    Write-Log "Driver Updater Auto-Start v4.3 Started" -Severity Info
    Write-Log "Running from: $script:ScriptPath" -Severity Info
    Write-Log "Is USB: $script:IsUSB" -Severity Info
    Write-Log $separator -Severity Info
    
    # Handle remove from startup parameter
    if ($RemoveFromStartup) {
        Remove-FromStartup
        exit 0
    }
    
    # Load current state
    $state = Get-UpdaterState
    $state.LastRun = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Install required modules
    if (-not (Install-RequiredModules)) {
        Write-Log "Failed to install required modules. Will retry on next run." -Severity Warning
        Set-UpdaterState -State $state
        exit 1
    }
    
    # Check for updates
    $updates = Get-AvailableUpdates
    
    if ($CheckOnly) {
        Write-Log "Check-only mode. Found $($updates.Count) updates." -Severity Info
        if ($updates.Count -gt 0) {
            foreach ($update in $updates) {
                Write-Log "  - $($update.Title)" -Severity Info
            }
        }
        exit 0
    }
    
    # Process updates
    if ($updates.Count -gt 0) {
        # Reset no-update counter
        $state.ConsecutiveNoUpdates = 0
        
        # Add to startup if not already added (first run)
        if ($state.InstallCount -eq 0) {
            Add-ToStartup
        }
        
        # Install updates
        $installedCount = Install-Updates -Updates $updates
        $state.InstallCount += $installedCount
        
        Write-Log "Installed $installedCount of $($updates.Count) updates" -Severity Info
        
        # Check if reboot is required
        $rebootRequired = Get-WURebootStatus -Silent
        if ($rebootRequired) {
            Write-Log "System reboot required. Updates will continue after restart." -Severity Warning
            Set-UpdaterState -State $state
            
            # Schedule reboot in 60 seconds
            Write-Log "Scheduling system restart in 60 seconds..." -Severity Warning
            shutdown /r /t 60 /c "System will restart in 60 seconds to complete driver installation. Save your work."
        }
    } else {
        # No updates found
        $state.ConsecutiveNoUpdates++
        Write-Log "No updates found. Consecutive count: $($state.ConsecutiveNoUpdates)" -Severity Info
        
        # If no updates found for 3 consecutive runs, consider complete
        if ($state.ConsecutiveNoUpdates -ge 3) {
            Write-Log "No updates found for 3 consecutive runs. Marking as complete." -Severity Success
            $state.IsComplete = $true
            
            # Remove from startup and clean up
            if (Remove-SelfAndCleanup) {
                $script:SkipFinalLog = $true
                exit 0
            }
        }
    }
    
    # Save state
    Set-UpdaterState -State $state
    
    Write-Log "Driver Updater completed successfully" -Severity Success
    
} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" -Severity Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Severity Error
    exit 1
} finally {
    if (-not $script:SkipFinalLog) {
        Write-Log ([string]::new('=', 60)) -Severity Info
    }
}
#endregion
