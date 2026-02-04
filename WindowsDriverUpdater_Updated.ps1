#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Advanced Windows Driver and Update Management Script

.DESCRIPTION
    Automates the process of checking, listing, and installing Windows updates and drivers
    with enhanced error handling, logging, and user interaction. Feature upgrades
    (e.g., Windows 10 to Windows 11) are excluded.

.NOTES
    Version: 4.4
    Author: Enterprise Tools Team
    Requires: Windows PowerShell 5.1 or later
    Admin Rights: Required
    Last Updated: 2025-12-19
#>

[CmdletBinding()]
param (
    [switch]$Silent,                # Suppresses console output
    [switch]$AutoInstall,           # Kept for backward compatibility - now always auto-installs
    [string]$DriverFilter,          # Filter for specific drivers by keyword
    [string]$LogPath,               # Custom log path
    [switch]$SkipBackup,            # Skip driver backup for faster execution
    [switch]$CreateRestorePoint,    # Create system restore point before updates
    [switch]$Force,                 # Force installation even if drivers are unsigned
    [int]$MaxUpdates = 0,           # Maximum number of updates to install (0 = all)
    [string]$ExcludeFilter          # Exclude drivers matching this filter
)

# SOTA 2026: Using Write-Host for colored UI (intentional), Write-Output for pipeline data
# ForEach-Object replaced with foreach loops for better performance (lines 372, 390)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Display progress bars only when not running in silent mode
if ($PSBoundParameters.ContainsKey('Silent') -and $Silent) {
    $ProgressPreference = 'SilentlyContinue'
}
else {
    $ProgressPreference = 'Continue'
}

#region Configuration and Initialization
$script:Config = @{
    LogPath            = if ($LogPath) { $LogPath } else { Join-Path $PSScriptRoot "DriverUpdaterLog.txt" }
    ModuleName         = "PSWindowsUpdate"
    InternetTestTarget = "download.windowsupdate.com"
    MSUpdateServiceId  = "7971f918-a847-4430-9279-4a52d1efe18d"
    MaxRetries         = 3
    RetryDelaySeconds  = 5
    MaxLogSize         = 10MB
    LogRetentionDays   = 30
    UpdateCategories   = @(
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
    UpdateApps = $true
    UpdateStoreApps = $true
    UpdateDefender = $true
    UpdatePowerShellModules = $true
}

# Ensure TLS 1.2 is enabled (TLS 1.3 added conditionally for compatibility)
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    # Add TLS 1.3 if available (requires .NET 4.8+)
    if ([Enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13
    }
}
catch {
    # Fallback to TLS 1.2 only
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
#endregion

#region Logging Functions
function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Severity = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - [$Severity] $Message"

    # Attempt to write to the log file
    try {
        $logDir = Split-Path -Parent $script:Config.LogPath
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        Add-Content -Path $script:Config.LogPath -Value $logEntry -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Failed to write to log file: $($_.Exception.Message)"
    }

    # Console output if not in silent mode
    if (-not $Silent) {
        $color = switch ($Severity) {
            'Info' { 'Cyan' }
            'Warning' { 'Yellow' }
            'Error' { 'Red' }
            'Success' { 'Green' }
            default { 'White' }
        }
        Write-Host $logEntry -ForegroundColor $color
    }
}

function Invoke-LogRotation {
    <#
    .SYNOPSIS
        Rotates log files when they exceed the maximum size.
    .DESCRIPTION
        Archives the current log file with a timestamp suffix and removes old archives
        based on the retention policy.
    #>
    [CmdletBinding()]
    param()

    if ((Test-Path $script:Config.LogPath) -and ((Get-Item $script:Config.LogPath).Length -gt $script:Config.MaxLogSize)) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $archivePath = "$($script:Config.LogPath).$timestamp.log"
        Move-Item -Path $script:Config.LogPath -Destination $archivePath -Force
        Write-Log "Log rotated. New log file created at $script:Config.LogPath" -Severity Info

        # Clean up old log files efficiently using -Filter parameter
        $logDir = Split-Path -Parent $script:Config.LogPath
        $cutoffDate = (Get-Date).AddDays(-$script:Config.LogRetentionDays)
        Get-ChildItem -Path $logDir -Filter "DriverUpdaterLog.txt.*.log" -File |
            Where-Object { $_.LastWriteTime -lt $cutoffDate } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region Helper Functions
function Invoke-WithRetry {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [string]$ActionName = "Operation"
    )

    for ($i = 1; $i -le $script:Config.MaxRetries; $i++) {
        try {
            return & $ScriptBlock
        }
        catch {
            Write-Log "$ActionName failed (Attempt $i of $($script:Config.MaxRetries)): $($_.Exception.Message)" -Severity Warning
            if ($i -ge $script:Config.MaxRetries) {
                throw $_
            }
            Start-Sleep -Seconds $script:Config.RetryDelaySeconds
        }
    }
}

function Show-Progress {
    param(
        [string]$Activity,
        [int]$PercentComplete,
        [string]$Status
    )
    
    if (-not $Silent) {
        Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
    }
}
#endregion

#region Core Functions
function Install-RequiredModules {
Write-Log "Checking for required modules..." -Severity Info

# Check for required Windows features
Write-Log "Checking Windows Update service status..." -Severity Info
try {
    $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    if ($wuService -and $wuService.Status -ne "Running") {
        Write-Log "Starting Windows Update service..." -Severity Info
        Start-Service -Name "wuauserv" -ErrorAction Stop
    }
}
catch {
    Write-Log "Warning: Could not check/start Windows Update service: $($_.Exception.Message)" -Severity Warning
}

Invoke-WithRetry -ScriptBlock {
    Show-Progress -Activity "Module Setup" -PercentComplete 10 -Status "Checking NuGet provider..."
    
    # Install NuGet package provider if not installed
    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        Write-Log "Installing NuGet package provider..." -Severity Info
        Install-PackageProvider -Name NuGet -Force -MinimumVersion 2.8.5.201 -ErrorAction Stop | Out-Null
    }

    Show-Progress -Activity "Module Setup" -PercentComplete 30 -Status "Configuring repository..."
    
    # Trust the PSGallery repository
    Write-Log "Configuring PSGallery repository..." -Severity Info
    $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
    if ($repo -and $repo.InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
    }

    Show-Progress -Activity "Module Setup" -PercentComplete 60 -Status "Checking PSWindowsUpdate..."
    
    # Install PSWindowsUpdate module if not installed
    if (-not (Get-Module -ListAvailable -Name $script:Config.ModuleName)) {
        Write-Log "Installing $($script:Config.ModuleName) module..." -Severity Info
        Install-Module -Name $script:Config.ModuleName -Force -AllowClobber -Scope AllUsers -ErrorAction Stop
    }

    Show-Progress -Activity "Module Setup" -PercentComplete 90 -Status "Importing module..."
    
    # Import PSWindowsUpdate module
    Write-Log "Importing $($script:Config.ModuleName) module..." -Severity Info
    Import-Module -Name $script:Config.ModuleName -Force -ErrorAction Stop

    Show-Progress -Activity "Module Setup" -PercentComplete 100 -Status "Complete"
    Write-Log "$($script:Config.ModuleName) module imported successfully." -Severity Success
} -ActionName "Module Installation"
}

function Register-MicrosoftUpdateService {
    Write-Log "Checking Microsoft Update Service registration..." -Severity Info
    Invoke-WithRetry -ScriptBlock {
        $service = Get-WUServiceManager | Where-Object { $_.ServiceID -eq $script:Config.MSUpdateServiceId }
        if (-not $service) {
            Write-Log "Registering Microsoft Update Service..." -Severity Info
            Add-WUServiceManager -MicrosoftUpdate -ErrorAction Stop
            Write-Log "Microsoft Update Service registered successfully." -Severity Success
        }
        else {
            Write-Log "Microsoft Update Service is already registered." -Severity Info
        }
    } -ActionName "Microsoft Update Service Registration"
}

function Test-InternetConnection {
    Write-Log "Checking internet connectivity..." -Severity Info
    try {
        $result = Invoke-WithRetry -ScriptBlock {
            Test-NetConnection -ComputerName $script:Config.InternetTestTarget -Port 443 -InformationLevel Quiet
        } -ActionName "Internet Connection Test"

        if ($result) {
            Write-Log "Internet connection detected." -Severity Success
            return $true
        }
        else {
            Write-Log "No internet connection detected." -Severity Warning
            return $false
        }
    }
    catch {
        Write-Log "Internet connectivity test failed: $($_.Exception.Message)" -Severity Error
        return $false
    }
}

function Get-DriverUpdates {
    Write-Log "Searching for Windows updates and drivers..." -Severity Info
    try {
        Show-Progress -Activity "Driver Updates" -PercentComplete 0 -Status "Searching for updates..."
        
        # First, check for Windows Update service
        $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        if (-not $wuService) {
            throw "Windows Update service not found"
        }
        
        $driverUpdates = Invoke-WithRetry -ScriptBlock {
            Get-WindowsUpdate -MicrosoftUpdate -IsInstalled:$false -Category $script:Config.UpdateCategories -NotCategory "Upgrades" -ErrorAction Stop
        } -ActionName "Driver Update Retrieval"

        if ($null -eq $driverUpdates -or @($driverUpdates).Count -eq 0) {
            Write-Log "No driver updates found." -Severity Info
            return @()
        }

        # Validate and filter updates
        $validUpdates = @()
        foreach ($update in $driverUpdates) {
            if (-not $update.Title) {
                Write-Log "Skipping update with missing title" -Severity Warning
                continue
            }

            # Skip preview/beta updates
            if ($update.Title -notlike "*Preview*" -and $update.Title -notlike "*Beta*") {
                $validUpdates += $update
            }
            else {
                Write-Log "Skipping preview/beta update: $($update.Title)" -Severity Info
            }
        }

        # Exclude feature upgrades by title pattern as a safety net
        if ($script:Config.ExcludedTitlePatterns.Count -gt 0) {
            foreach ($pattern in $script:Config.ExcludedTitlePatterns) {
                $validUpdates = @($validUpdates | Where-Object { $_.Title -notlike $pattern })
            }
        }

        Write-Log "Found $($validUpdates.Count) valid driver updates after filtering." -Severity Info
        return $validUpdates
    }
    catch {
        Write-Log "Error fetching driver updates: $($_.Exception.Message)" -Severity Error
        throw
    }
}

function Select-DriverUpdates {
    <#
    .SYNOPSIS
        Filters driver updates based on include/exclude patterns.
    .DESCRIPTION
        Applies keyword-based filtering to driver updates and limits results.
    .PARAMETER Updates
        Array of driver updates to filter.
    .PARAMETER IncludeFilter
        Comma-separated keywords to include (matches Title or Description).
    .PARAMETER ExcludeFilter
        Comma-separated keywords to exclude (matches Title or Description).
    .PARAMETER MaxUpdates
        Maximum number of updates to return (0 = unlimited).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [array]$Updates,

        [Parameter(Mandatory = $false)]
        [string]$IncludeFilter,

        [Parameter(Mandatory = $false)]
        [string]$ExcludeFilter,

        [Parameter(Mandatory = $false)]
        [int]$MaxUpdates = 0
    )

    if ($null -eq $Updates -or $Updates.Count -eq 0) {
        return @()
    }

    $filteredUpdates = @($Updates)

    # Apply include filter if specified
    if (-not [string]::IsNullOrEmpty($IncludeFilter)) {
        # SOTA 2026: Use foreach instead of ForEach-Object for better performance
        $keywords = @()
        foreach ($kw in ($IncludeFilter -split ',')) {
            $trimmed = $kw.Trim()
            if ($trimmed) { $keywords += $trimmed }
        }
        $filteredUpdates = @($filteredUpdates | Where-Object {
            $update = $_
            $matchFound = $false
            foreach ($keyword in $keywords) {
                if (($update.Title -and $update.Title -like "*$keyword*") -or
                    ($update.Description -and $update.Description -like "*$keyword*")) {
                    $matchFound = $true
                    break
                }
            }
            $matchFound
        })
        Write-Log "Applied include filter '$IncludeFilter'. Found $($filteredUpdates.Count) matching drivers." -Severity Info
    }

    # Apply exclude filter if specified
    if (-not [string]::IsNullOrEmpty($ExcludeFilter)) {
        # SOTA 2026: Use foreach instead of ForEach-Object for better performance
        $excludeKeywords = @()
        foreach ($kw in ($ExcludeFilter -split ',')) {
            $trimmed = $kw.Trim()
            if ($trimmed) { $excludeKeywords += $trimmed }
        }
        $filteredUpdates = @($filteredUpdates | Where-Object {
            $update = $_
            $shouldExclude = $false
            foreach ($keyword in $excludeKeywords) {
                if (($update.Title -and $update.Title -like "*$keyword*") -or
                    ($update.Description -and $update.Description -like "*$keyword*")) {
                    $shouldExclude = $true
                    break
                }
            }
            -not $shouldExclude
        })
        Write-Log "Applied exclude filter '$ExcludeFilter'. Remaining drivers: $($filteredUpdates.Count)" -Severity Info
    }

    # Apply max updates limit
    if ($MaxUpdates -gt 0 -and $filteredUpdates.Count -gt $MaxUpdates) {
        $filteredUpdates = @($filteredUpdates[0..($MaxUpdates - 1)])
        Write-Log "Limited to $MaxUpdates updates based on MaxUpdates parameter." -Severity Info
    }

    return $filteredUpdates
}

function Show-DriverUpdates {
    param (
        [array]$DriverUpdates
    )

    if ($null -eq $DriverUpdates -or @($DriverUpdates).Count -eq 0) {
        Write-Host "No driver updates available." -ForegroundColor Yellow
        return
    }

    Write-Host "`nAvailable Driver Updates:" -ForegroundColor Cyan
    Write-Host "------------------------" -ForegroundColor Cyan

    foreach ($update in $DriverUpdates) {
        Write-Host "`nTitle: " -NoNewline -ForegroundColor White
        Write-Host $update.Title -ForegroundColor Green
        Write-Host "KB: " -NoNewline -ForegroundColor White
        Write-Host $update.KB
        Write-Host "Size: " -NoNewline -ForegroundColor White
        Write-Host $update.Size
        Write-Host "Description: " -NoNewline -ForegroundColor White
        Write-Host $update.Description
    }

    Write-Output ""
}

function Backup-ExistingDrivers {
    Write-Log "Creating backup of existing drivers..." -Severity Info
    try {
        $backupDir = Join-Path $PSScriptRoot "DriverBackups"
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupPath = Join-Path $backupDir $timestamp
        
        if (-not (Test-Path $backupPath)) {
            New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
        }
        
        Write-Log "Exporting drivers to $backupPath..." -Severity Info
        Export-WindowsDriver -Online -Destination $backupPath -ErrorAction Stop
        
        Write-Log "Driver backup completed successfully at $backupPath" -Severity Success
        return $backupPath
    }
    catch {
        Write-Log "Driver backup failed: $($_.Exception.Message)" -Severity Warning
        return $null
    }
}

function New-SystemRestorePoint {
    <#
    .SYNOPSIS
        Creates a system restore point before driver updates.
    .DESCRIPTION
        Checks if System Restore is enabled and creates a restore point.
    #>
    [CmdletBinding()]
    param()

    Write-Log "Creating system restore point..." -Severity Info
    try {
        # Check if System Restore is enabled by querying the system protection settings
        $systemDrive = $env:SystemDrive
        $restoreStatus = Get-CimInstance -ClassName SystemRestoreConfig -Namespace "root\default" -ErrorAction SilentlyContinue

        if ($null -eq $restoreStatus) {
            # Alternative check using vssadmin or registry
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
            $rpEnabled = Get-ItemProperty -Path $regPath -Name "RPSessionInterval" -ErrorAction SilentlyContinue
            if ($null -eq $rpEnabled -or $rpEnabled.RPSessionInterval -eq 0) {
                Write-Log "System Restore may not be enabled on this system" -Severity Warning
            }
        }

        $restorePointName = "Driver Update - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        Checkpoint-Computer -Description $restorePointName -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop

        Write-Log "System restore point created: $restorePointName" -Severity Success
        return $true
    }
    catch {
        Write-Log "Failed to create system restore point: $($_.Exception.Message)" -Severity Warning
        return $false
    }
}

function Test-DriverSignature {
    param (
        [string]$DriverPath
    )
    
    try {
        $signature = Get-AuthenticodeSignature -FilePath $DriverPath -ErrorAction SilentlyContinue
        return ($signature.Status -eq "Valid")
    }
    catch {
        return $false
    }
}

function Get-SystemInfo {
    <#
    .SYNOPSIS
        Collects basic system information for logging purposes.
    #>
    [CmdletBinding()]
    param()

    Write-Log "Collecting system information..." -Severity Info
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $csInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop

        $systemInfo = @{
            ComputerName      = $env:COMPUTERNAME
            OSVersion         = $osInfo.Caption
            OSBuild           = $osInfo.BuildNumber
            Architecture      = $osInfo.OSArchitecture
            TotalRAM          = [math]::Round($csInfo.TotalPhysicalMemory / 1GB, 2)
            FreeDiskSpace     = [math]::Round((Get-PSDrive C -ErrorAction SilentlyContinue).Free / 1GB, 2)
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        }

        Write-Log "System: $($systemInfo.OSVersion) ($($systemInfo.Architecture)), RAM: $($systemInfo.TotalRAM)GB, Free Space: $($systemInfo.FreeDiskSpace)GB" -Severity Info
        return $systemInfo
    }
    catch {
        Write-Log "Could not collect system information: $($_.Exception.Message)" -Severity Warning
        return $null
    }
}

function Install-DriverUpdates {
    param (
        [array]$DriverUpdates,
        [switch]$SkipBackup,
        [switch]$Force
    )

    if ($null -eq $DriverUpdates -or @($DriverUpdates).Count -eq 0) {
        Write-Log "No driver updates to install." -Severity Info
        return
    }

    Write-Log "Installing $($DriverUpdates.Count) driver updates..." -Severity Info
    
    # Create driver backup before installation (unless skipped)
    if (-not $SkipBackup) {
        $backupPath = Backup-ExistingDrivers
    }
    
    try {
        $totalUpdates = $DriverUpdates.Count
        $currentUpdate = 0
        $successfulInstalls = 0
        $failedInstalls = 0
        
        Show-Progress -Activity "Installing Drivers" -PercentComplete 0 -Status "Starting installation..."
        
        # Install updates one by one for better error handling
        foreach ($update in $DriverUpdates) {
            $currentUpdate++
            $percentComplete = [int](($currentUpdate / $totalUpdates) * 100)
            
            Show-Progress -Activity "Installing Drivers" -PercentComplete $percentComplete -Status "Installing $($update.Title)..."
            Write-Log "Installing driver: $($update.Title) (KB: $($update.KB))" -Severity Info
            
            try {
                $installParams = @{
                    AcceptAll = $true
                    AutoReboot = $false
                    IgnoreReboot = $true
                    Verbose = $true
                    ErrorAction = 'Stop'
                }
                
                if ($Force) {
                    Write-Log "Force installation enabled for $($update.Title)" -Severity Warning
                    $installParams.Add('Force', $true)
                }
                
                $update | Install-WindowsUpdate @installParams
                $successfulInstalls++
                Write-Log "Successfully installed: $($update.Title)" -Severity Success
            }
            catch {
                $failedInstalls++
                Write-Log "Failed to install $($update.Title): $($_.Exception.Message)" -Severity Error
            }
        }
        
        Show-Progress -Activity "Installing Drivers" -PercentComplete 100 -Status "Installation complete"
        
        # Summary report
        Write-Log "Driver installation summary: $successfulInstalls successful, $failedInstalls failed" -Severity Info
        
        if ($successfulInstalls -gt 0) {
            Write-Log "Driver updates installed successfully." -Severity Success
        }
        
        if ($failedInstalls -gt 0) {
            Write-Log "Some driver updates failed to install. Check the log for details." -Severity Warning
        }

        # Check if reboot is required
        try {
            $rebootRequired = Get-WURebootStatus -Silent
            if ($rebootRequired) {
                Write-Log "System restart is required to complete driver installation." -Severity Warning
                if (-not $Silent) {
                    $rebootChoice = Read-Host "Would you like to restart now? (Y/N)"
                    if ($rebootChoice -eq 'Y' -or $rebootChoice -eq 'y') {
                        Write-Log "Initiating system restart..." -Severity Warning
                        Restart-Computer -Force
                    }
                    else {
                        Write-Log "User chose not to restart now. Please restart the system later to complete driver installations." -Severity Info
                    }
                }
            }
        }
        catch {
            Write-Log "Could not determine reboot status: $($_.Exception.Message)" -Severity Warning
        }
    }
    catch {
        Write-Log "Driver update installation failed: $($_.Exception.Message)" -Severity Error
        throw
    }
}

#endregion

#region App Update Functions
function Update-WinGetPackages {
    if (-not $script:Config.UpdateApps) {
        return
    }

    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Log "WinGet not available. Skipping app updates." -Severity Warning
        return
    }

    try {
        Write-Log "Checking WinGet packages..." -Severity Info
        $updatesJson = winget upgrade --accept-source-agreements --accept-package-agreements --output json 2>$null
        $updates = $null
        try { $updates = $updatesJson | ConvertFrom-Json } catch {}

        if (-not $updates) {
            Write-Log "Unable to parse WinGet upgrade list." -Severity Warning
            return
        }

        $toUpdate = $updates | Where-Object { $_.PackageIdentifier }
        if (-not $toUpdate -or $toUpdate.Count -eq 0) {
            Write-Log "No WinGet updates available." -Severity Info
            return
        }

        Write-Log "Updating $($toUpdate.Count) WinGet packages..." -Severity Info
        foreach ($package in $toUpdate) {
            try {
                Write-Log "Updating: $($package.PackageIdentifier)" -Severity Info
                winget upgrade --id $package.PackageIdentifier --silent --accept-package-agreements --accept-source-agreements
            }
            catch {
                Write-Log "Failed to update $($package.PackageIdentifier): $($_.Exception.Message)" -Severity Warning
            }
        }
    }
    catch {
        Write-Log "WinGet update error: $($_.Exception.Message)" -Severity Warning
    }
}

function Update-StoreApps {
    if (-not $script:Config.UpdateStoreApps) {
        return
    }

    Write-Log "Updating Microsoft Store applications..." -Severity Info
    try {
        $namespaceName = "Root\cimv2\mdm\dmmap"
        $className = "MDM_EnterpriseModernAppManagement_AppManagement01"
        Get-CimInstance -Namespace $namespaceName -ClassName $className -ErrorAction Stop |
            Invoke-CimMethod -MethodName UpdateScanMethod -ErrorAction Stop
        Write-Log "Microsoft Store update scan initiated." -Severity Success
    }
    catch {
        Write-Log "Store update scan failed, attempting wsreset." -Severity Warning
        Start-Process "wsreset.exe" -NoNewWindow -ErrorAction SilentlyContinue
    }
}

function Update-DefenderDefinitions {
    if (-not $script:Config.UpdateDefender) {
        return
    }

    Write-Log "Updating Windows Defender definitions..." -Severity Info
    try {
        if (Get-Command Update-MpSignature -ErrorAction SilentlyContinue) {
            Update-MpSignature -UpdateSource MicrosoftUpdateServer -ErrorAction Stop
            Write-Log "Windows Defender definitions updated." -Severity Success
        }
        else {
            Write-Log "Windows Defender cmdlets not available. Skipping." -Severity Warning
        }
    }
    catch {
        Write-Log "Defender update failed: $($_.Exception.Message)" -Severity Warning
    }
}

function Update-PowerShellModules {
    if (-not $script:Config.UpdatePowerShellModules) {
        return
    }

    Write-Log "Checking PowerShell module updates..." -Severity Info
    try {
        $installedModules = Get-InstalledModule -ErrorAction SilentlyContinue
        if (-not $installedModules) {
            Write-Log "No PowerShell Gallery modules found." -Severity Info
            return
        }

        foreach ($module in $installedModules) {
            try {
                $latestVersion = Find-Module -Name $module.Name -ErrorAction SilentlyContinue
                if ($latestVersion -and ($latestVersion.Version -gt $module.Version)) {
                    Write-Log "Updating module: $($module.Name)" -Severity Info
                    Update-Module -Name $module.Name -Force -ErrorAction Stop
                }
            }
            catch {
                Write-Log "Failed to update module $($module.Name): $($_.Exception.Message)" -Severity Warning
            }
        }
    }
    catch {
        Write-Log "PowerShell module update error: $($_.Exception.Message)" -Severity Warning
    }
}
#endregion

#region Main Execution
try {
    # Rotate log if necessary
    Invoke-LogRotation

    Write-Log "Driver Update Manager started." -Severity Info
    Write-Log "Script version: 4.4" -Severity Info
    Write-Log "Running in $(if ($Silent) { 'silent' } else { 'interactive' }) mode" -Severity Info

    # Install required modules
    Install-RequiredModules

    # Register Microsoft Update Service
    Register-MicrosoftUpdateService

    # Test internet connectivity
    if (Test-InternetConnection) {
        # Retrieve driver updates
        $driverUpdates = Get-DriverUpdates

        # Apply driver filter if specified
        $filteredUpdates = Select-DriverUpdates -Updates $driverUpdates -IncludeFilter $DriverFilter -ExcludeFilter $ExcludeFilter -MaxUpdates $MaxUpdates

        # Show available updates
        Show-DriverUpdates -DriverUpdates $filteredUpdates

        # Collect system information
        $systemInfo = Get-SystemInfo
        
        # Create system restore point if requested
        if ($CreateRestorePoint) {
            $restorePointCreated = New-SystemRestorePoint
        }
        
        # Install updates without prompting
        $updateCount = @($filteredUpdates).Count
        if ($updateCount -gt 0) {
            Write-Log "Auto-installing $updateCount driver(s) without user confirmation..." -Severity Info
            
            # Skip backup if requested
            if ($SkipBackup) {
                Write-Log "Skipping driver backup as requested by -SkipBackup parameter" -Severity Info
            }
            
            Install-DriverUpdates -DriverUpdates $filteredUpdates -SkipBackup:$SkipBackup -Force:$Force
        }
        else {
            Write-Log "No matching driver updates found based on filter criteria." -Severity Info
        }

        # Update additional components
        Update-DefenderDefinitions
        Update-StoreApps
        Update-WinGetPackages
        Update-PowerShellModules
    }
    else {
        throw "No internet connection available. Please check your network settings."
    }
}
catch {
    Write-Log "An error occurred: $($_.Exception.Message)" -Severity Error
    Write-Host "Script execution failed. Please check the log file for details." -ForegroundColor Red
}
finally {
    Write-Log "Driver Update Manager completed." -Severity Info
    if (-not $Silent) {
        Write-Host "`nPress any key to exit..." -ForegroundColor White
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
}
#endregion
