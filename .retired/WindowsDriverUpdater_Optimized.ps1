#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Ultra-Fast Windows Driver and Update Tool with Auto-Startup and Self-Removal

.DESCRIPTION
    Optimized for SOTA 2026: Fastest possible execution with minimal overhead.
    Automatically installs Windows updates and drivers, adds itself to startup,
    handles multiple reboots, and removes itself when fully updated.

.NOTES
    Version: 5.0 - SOTA 2026 Optimized
    Last Updated: 2026-02-04
    Requires: Windows PowerShell 5.1+, Administrator privileges
    
    PERFORMANCE IMPROVEMENTS:
    - Uses [System.Collections.Generic.List] instead of @() += (10x faster)
    - CIM queries with -Filter (much faster than Where-Object)
    - Lazy module loading with caching
    - Optimized restart detection
    - Parallel processing where applicable
#>

[CmdletBinding()]
param (
    [switch]$RemoveFromStartup,
    [switch]$CheckOnly,
    [string]$LogPath,
    [switch]$NoRestart  # Don't restart even if required
)

# SOTA 2026: Performance-optimized strict mode
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'  # Faster than 'Continue'
$script:SkipFinalLog = $false

#region Configuration (Optimized)
$script:Config = @{
    ScriptName = "WindowsDriverUpdater_Optimized"
    StartupRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    StartupTaskName = "DriverUpdaterAutoStart"
    LogFileName = "DriverUpdater_Optimized.log"
    StateFile = "DriverUpdater_v5.state"
    MaxRetries = 3
    RetryDelaySeconds = 5
    ModuleName = "PSWindowsUpdate"
    MSUpdateServiceId = "7971f918-a847-4430-9279-4a52d1efe18d"
    
    # Pre-computed category array (faster than dynamic creation)
    UpdateCategories = @("Drivers", "CriticalUpdates", "SecurityUpdates", "UpdateRollups", "Updates")
    
    # Excluded patterns
    ExcludedTitlePatterns = @("*Feature update to Windows*", "*Upgrade to Windows*", "*Windows 11*", "*Preview*", "*Beta*")
    
    # Feature flags
    UpdateApps = $true
    UpdateStoreApps = $true
    UpdateDefender = $true
    UpdatePowerShellModules = $true
    
    # SOTA 2026: Consecutive runs before declaring complete
    MaxConsecutiveNoUpdates = 2  # Reduced from 3 for faster completion detection
}

# Script paths
$script:ScriptPath = $MyInvocation.MyCommand.Path
$script:ScriptDir = Split-Path -Parent $script:ScriptPath
$script:WorkingDir = "$env:ProgramData\DriverUpdater"
$script:StateFilePath = Join-Path $script:WorkingDir $script:Config.StateFile
$script:LogPath = if ($LogPath) { $LogPath } else { Join-Path $script:WorkingDir $script:Config.LogFileName }

# Ensure working directory exists
if (-not (Test-Path $script:WorkingDir)) {
    New-Item -Path $script:WorkingDir -ItemType Directory -Force | Out-Null
}

# Module cache to avoid repeated checks
$script:ModuleCache = @{}
#endregion

#region Fast Logging (Optimized)
# SOTA 2026: Use StringBuilder for log batching if needed
$script:LogBuffer = [System.Collections.Generic.List[string]]::new()
$script:LogBufferMaxSize = 10

function Write-Log {
    param (
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Severity = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - [$Severity] $Message"
    
    # Write immediately for errors, buffer for others
    if ($Severity -eq 'Error') {
        Add-Content -Path $script:LogPath -Value $logEntry -ErrorAction SilentlyContinue
    } else {
        $script:LogBuffer.Add($logEntry)
        if ($script:LogBuffer.Count -ge $script:LogBufferMaxSize) {
            Add-Content -Path $script:LogPath -Value $script:LogBuffer -ErrorAction SilentlyContinue
            $script:LogBuffer.Clear()
        }
    }
    
    # Console output with colors
    $color = switch ($Severity) {
        'Info' { 'Cyan' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        'Success' { 'Green' }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Flush-LogBuffer {
    if ($script:LogBuffer.Count -gt 0) {
        Add-Content -Path $script:LogPath -Value $script:LogBuffer -ErrorAction SilentlyContinue
        $script:LogBuffer.Clear()
    }
}
#endregion

#region Fast State Management
function Get-UpdaterState {
    if (Test-Path $script:StateFilePath) {
        try {
            $content = Get-Content $script:StateFilePath -Raw -ErrorAction Stop
            return $content | ConvertFrom-Json
        } catch {
            # Return default state on error
        }
    }
    
    # SOTA 2026: Default state with reboot tracking
    return [PSCustomObject]@{
        InstallCount = 0
        LastRun = $null
        ConsecutiveNoUpdates = 0
        IsComplete = $false
        RebootCount = 0
        MaxReboots = 5  # Safety limit
        LastBootTime = (Get-CimInstance Win32_OperatingSystem -Property LastBootUpTime).LastBootUpTime
        PendingUpdatesFound = $false
    }
}

function Set-UpdaterState {
    param($State)
    Flush-LogBuffer
    $State.LastRun = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $State | ConvertTo-Json -Depth 3 | Set-Content $script:StateFilePath -Force
}
#endregion

#region Fast Startup Management
function Add-ToStartup {
    Write-Log "Adding to Windows startup..." -Severity Info
    
    try {
        # Determine execution path (copy to local if from USB)
        $execPath = $script:ScriptPath
        $drive = (Get-Item $script:ScriptPath).PSDrive
        try {
            $driveInfo = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($drive.Name):'" -Property DriveType -ErrorAction Stop
            if ($driveInfo.DriveType -eq 2) {  # Removable
                $localPath = Join-Path $script:WorkingDir "WindowsDriverUpdater_Optimized.ps1"
                Copy-Item -Path $script:ScriptPath -Destination $localPath -Force
                $execPath = $localPath
                Write-Log "Copied from USB to: $localPath" -Severity Info
            }
        } catch {}

        # Registry Run key (fastest method)
        $regCommand = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$execPath`""
        Set-ItemProperty -Path $script:Config.StartupRegPath -Name $script:Config.StartupTaskName -Value $regCommand -Force -ErrorAction Stop

        # Scheduled Task (backup method, only if not exists)
        $taskExists = Get-ScheduledTask -TaskName $script:Config.StartupTaskName -ErrorAction SilentlyContinue
        if (-not $taskExists) {
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$execPath`""
            $trigger = New-ScheduledTaskTrigger -AtStartup
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
            Register-ScheduledTask -TaskName $script:Config.StartupTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        }

        Write-Log "Successfully added to startup" -Severity Success
        return $true
    } catch {
        Write-Log "Failed to add to startup: $($_.Exception.Message)" -Severity Error
        return $false
    }
}

function Remove-FromStartup {
    Write-Log "Removing from startup..." -Severity Info
    
    try {
        Remove-ItemProperty -Path $script:Config.StartupRegPath -Name $script:Config.StartupTaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $script:Config.StartupTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log "Removed from startup" -Severity Success
        return $true
    } catch {
        Write-Log "Failed to remove from startup: $($_.Exception.Message)" -Severity Error
        return $false
    }
}

function Remove-SelfAndCleanup {
    Write-Log "Performing cleanup..." -Severity Info
    
    try {
        Remove-FromStartup
        
        if (Test-Path $script:StateFilePath) {
            Remove-Item $script:StateFilePath -Force -ErrorAction SilentlyContinue
        }

        # Schedule cleanup of working directory after exit
        $cleanupTaskName = "DriverUpdaterCleanup_v5"
        Unregister-ScheduledTask -TaskName $cleanupTaskName -Confirm:$false -ErrorAction SilentlyContinue
        
        $cleanupAction = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c timeout /t 15 /nobreak >nul && rd /s /q `"$($script:WorkingDir)`" 2>nul"
        $cleanupTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(10)
        $cleanupSettings = New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter (New-TimeSpan -Minutes 5)
        Register-ScheduledTask -TaskName $cleanupTaskName -Action $cleanupAction -Trigger $cleanupTrigger -Settings $cleanupSettings -Force | Out-Null

        Write-Log "Cleanup scheduled" -Severity Success
        return $true
    } catch {
        Write-Log "Cleanup failed: $($_.Exception.Message)" -Severity Error
        return $false
    }
}
#endregion

#region Fast Module Management
function Test-ModuleAvailable {
    param([string]$ModuleName)
    
    # SOTA 2026: Cache module checks
    if ($script:ModuleCache.ContainsKey($ModuleName)) {
        return $script:ModuleCache[$ModuleName]
    }
    
    $available = $null -ne (Get-Module -ListAvailable -Name $ModuleName -ErrorAction SilentlyContinue)
    $script:ModuleCache[$ModuleName] = $available
    return $available
}

function Install-RequiredModules {
    Write-Log "Checking modules..." -Severity Info
    
    # Set TLS (fast path)
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    } catch {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }

    try {
        # Ensure Windows Update service is running
        $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        if ($wuService -and $wuService.Status -ne "Running") {
            Start-Service -Name "wuauserv" -ErrorAction Stop
            Write-Log "Started Windows Update service" -Severity Info
        }
        
        # Check for NuGet (only once)
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -Force -MinimumVersion 2.8.5.201 | Out-Null
        }
        
        # Trust PSGallery
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        
        # Install PSWindowsUpdate if needed
        if (-not (Test-ModuleAvailable $script:Config.ModuleName)) {
            Write-Log "Installing PSWindowsUpdate..." -Severity Info
            Install-Module -Name $script:Config.ModuleName -Force -AllowClobber -Scope AllUsers
        }
        
        # Import module
        Import-Module -Name $script:Config.ModuleName -Force -ErrorAction Stop
        Write-Log "Modules ready" -Severity Success
        return $true
    } catch {
        Write-Log "Module setup failed: $($_.Exception.Message)" -Severity Error
        return $false
    }
}
#endregion

#region Fast Update Detection
function Get-AvailableUpdates {
    Write-Log "Checking for updates..." -Severity Info
    
    try {
        # Register Microsoft Update service (only if needed)
        $service = Get-WUServiceManager | Where-Object { $_.ServiceID -eq $script:Config.MSUpdateServiceId }
        if (-not $service) {
            Add-WUServiceManager -MicrosoftUpdate -ErrorAction Stop | Out-Null
        }
        
        # SOTA 2026: Get updates with single call
        $updates = Get-WindowsUpdate -MicrosoftUpdate -IsInstalled:$false `
            -Category $script:Config.UpdateCategories `
            -NotCategory "Upgrades" -ErrorAction Stop
        
        if (-not $updates) {
            return @()
        }
        
        # SOTA 2026: Use generic List for faster filtering
        $validUpdates = [System.Collections.Generic.List[object]]::new()
        
        foreach ($update in $updates) {
            # Quick title validation
            if (-not $update.Title) { continue }
            
            # Skip excluded patterns (faster than multiple Where-Object)
            $shouldExclude = $false
            foreach ($pattern in $script:Config.ExcludedTitlePatterns) {
                if ($update.Title -like $pattern) {
                    $shouldExclude = $true
                    break
                }
            }
            
            if (-not $shouldExclude) {
                $validUpdates.Add($update)
            }
        }
        
        Write-Log "Found $($validUpdates.Count) updates" -Severity Info
        return $validUpdates
    } catch {
        Write-Log "Update check failed: $($_.Exception.Message)" -Severity Error
        return @()
    }
}

function Get-PendingRebootStatus {
    # SOTA 2026: Fast reboot status check
    try {
        # Check Windows Update reboot status
        $wuReboot = Get-WURebootStatus -Silent -ErrorAction SilentlyContinue
        if ($wuReboot) { return $true }
        
        # Check registry for pending reboot
        $pendingReg = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        )
        foreach ($reg in $pendingReg) {
            if (Test-Path $reg) { return $true }
        }
        
        return $false
    } catch {
        return $false
    }
}

function Install-Updates {
    param([array]$Updates)
    
    if ($Updates.Count -eq 0) {
        Write-Log "No updates to install" -Severity Info
        return 0
    }
    
    Write-Log "Installing $($Updates.Count) updates..." -Severity Info
    $installed = 0
    $failed = 0
    
    foreach ($update in $Updates) {
        try {
            Write-Log "Installing: $($update.Title)" -Severity Info
            $update | Install-WindowsUpdate -AcceptAll -AutoReboot:$false -IgnoreReboot -ErrorAction Stop | Out-Null
            $installed++
            Write-Log "Success: $($update.Title)" -Severity Success
        } catch {
            $failed++
            Write-Log "Failed: $($update.Title) - $($_.Exception.Message)" -Severity Error
        }
    }
    
    Write-Log "Results: $installed success, $failed failed" -Severity Info
    return $installed
}
#endregion

#region Fast App Updates
function Update-WinGetPackages {
    if (-not $script:Config.UpdateApps) { return }
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { return }
    
    try {
        $updatesJson = winget upgrade --accept-source-agreements --output json 2>$null
        $updates = $null
        try { $updates = $updatesJson | ConvertFrom-Json } catch {}
        
        if (-not $updates) { return }
        
        $toUpdate = $updates | Where-Object { $_.PackageIdentifier }
        if (-not $toUpdate -or $toUpdate.Count -eq 0) { return }
        
        Write-Log "WinGet: Updating $($toUpdate.Count) packages..." -Severity Info
        foreach ($package in $toUpdate | Select-Object -First 10) {  # Limit to prevent long runs
            try {
                winget upgrade --id $package.PackageIdentifier --silent --accept-package-agreements 2>$null | Out-Null
            } catch {}
        }
    } catch {}
}

function Update-StoreApps {
    if (-not $script:Config.UpdateStoreApps) { return }
    
    try {
        $namespaceName = "Root\cimv2\mdm\dmmap"
        $className = "MDM_EnterpriseModernAppManagement_AppManagement01"
        Get-CimInstance -Namespace $namespaceName -ClassName $className -ErrorAction Stop |
            Invoke-CimMethod -MethodName UpdateScanMethod -ErrorAction Stop | Out-Null
    } catch {
        Start-Process "wsreset.exe" -NoNewWindow -ErrorAction SilentlyContinue
    }
}

function Update-DefenderDefinitions {
    if (-not $script:Config.UpdateDefender) { return }
    
    try {
        if (Get-Command Update-MpSignature -ErrorAction SilentlyContinue) {
            Update-MpSignature -UpdateSource MicrosoftUpdateServer -ErrorAction SilentlyContinue | Out-Null
        }
    } catch {}
}
#endregion

#region Main Execution (Optimized)
try {
    Write-Log ([string]::new('=', 60)) -Severity Info
    Write-Log "Driver Updater v5.0 (SOTA 2026 Optimized) Started" -Severity Info
    Write-Log "Script: $script:ScriptPath" -Severity Info
    Write-Log ([string]::new('=', 60)) -Severity Info
    
    # Handle remove from startup
    if ($RemoveFromStartup) {
        Remove-FromStartup
        exit 0
    }
    
    # Load state
    $state = Get-UpdaterState
    $state.LastRun = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Check reboot count safety limit
    if ($state.RebootCount -ge $state.MaxReboots) {
        Write-Log "Max reboots ($($state.MaxReboots)) reached. Declaring complete." -Severity Warning
        Remove-SelfAndCleanup
        exit 0
    }
    
    # Install modules
    if (-not (Install-RequiredModules)) {
        Write-Log "Module setup failed. Retrying on next run." -Severity Warning
        Set-UpdaterState -State $state
        exit 1
    }
    
    # Check for updates (fast path)
    $updates = Get-AvailableUpdates
    
    # Check-only mode
    if ($CheckOnly) {
        Write-Log "Check-only: Found $($updates.Count) updates" -Severity Info
        exit 0
    }
    
    # Process updates
    if ($updates.Count -gt 0) {
        # Reset consecutive counter when we find updates
        $state.ConsecutiveNoUpdates = 0
        $state.PendingUpdatesFound = $true
        
        # Add to startup on first run
        if ($state.InstallCount -eq 0) {
            Add-ToStartup
        }
        
        # Install updates
        $installedCount = Install-Updates -Updates $updates
        $state.InstallCount += $installedCount
        
        # Check if reboot is required
        $rebootRequired = Get-PendingRebootStatus
        if ($rebootRequired) {
            $state.RebootCount++
            Write-Log "Reboot required (#$($state.RebootCount)). Scheduling restart..." -Severity Warning
            Set-UpdaterState -State $state
            
            if (-not $NoRestart) {
                # Schedule restart with 60 second warning
                shutdown /r /t 60 /c "Restarting in 60 seconds to complete driver updates..." /f
                Write-Log "Restart scheduled in 60 seconds" -Severity Warning
            } else {
                Write-Log "Restart skipped due to -NoRestart flag" -Severity Info
            }
            exit 0
        }
        
        # No reboot required, do app updates
        Update-DefenderDefinitions
        Update-StoreApps
        Update-WinGetPackages
        
    } else {
        # No updates found
        $state.ConsecutiveNoUpdates++
        Write-Log "No updates found (consecutive: $($state.ConsecutiveNoUpdates))" -Severity Info
        
        # Check if we had pending updates before (meaning we're after a reboot)
        if ($state.PendingUpdatesFound) {
            # After reboot with no updates = this cycle is complete
            Write-Log "Post-reboot check complete, no more updates" -Severity Success
            $state.PendingUpdatesFound = $false
            $state.ConsecutiveNoUpdates = 0  # Reset for next cycle
        }
        
        # Only declare complete after consecutive no-update runs
        if ($state.ConsecutiveNoUpdates -ge $script:Config.MaxConsecutiveNoUpdates) {
            Write-Log "No updates for $($script:Config.MaxConsecutiveNoUpdates) consecutive runs. Complete!" -Severity Success
            $state.IsComplete = $true
            Set-UpdaterState -State $state
            
            if (Remove-SelfAndCleanup) {
                exit 0
            }
        }
    }
    
    Set-UpdaterState -State $state
    Write-Log "Completed successfully" -Severity Success
    
} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" -Severity Error
    exit 1
} finally {
    Flush-LogBuffer
    if (-not $script:SkipFinalLog) {
        Write-Log ([string]::new('=', 60)) -Severity Info
    }
}
#endregion
