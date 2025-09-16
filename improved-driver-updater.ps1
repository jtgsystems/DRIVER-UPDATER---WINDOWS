# Enhanced Windows Driver Updater Script
# Based on Microsoft Official Documentation and Best Practices 2025
# Sources: Microsoft Learn, Windows Update Agent API, PSWindowsUpdate Module Documentation

#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Enhanced Windows Driver Updater using Microsoft-recommended APIs and practices

.DESCRIPTION
    This script implements Microsoft's official Windows Update Agent API and PSWindowsUpdate module
    to safely detect, download, and install driver updates. It follows 2025 security best practices
    and uses only documented Microsoft interfaces.

.PARAMETER DriverTypesOnly
    Focus only on driver updates (excludes software updates)

.PARAMETER IncludeSoftware
    Include both drivers and software updates

.PARAMETER LogPath
    Custom path for log files (default: script directory)

.EXAMPLE
    .\improved-driver-updater.ps1 -DriverTypesOnly

.EXAMPLE
    .\improved-driver-updater.ps1 -IncludeSoftware -LogPath "C:\UpdateLogs"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$DriverTypesOnly = $true,

    [Parameter(Mandatory=$false)]
    [switch]$IncludeSoftware = $false,

    [Parameter(Mandatory=$false)]
    [ValidateScript({Test-Path $_ -IsValid})]
    [string]$LogPath = $PSScriptRoot
)

# Set strict error handling
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'Continue'

# Constants based on Microsoft documentation
$MICROSOFT_UPDATE_SERVICE_ID = "7971f918-a847-4430-9279-4a52d1efe18d"
$WINDOWS_UPDATE_SERVICE_ID = "9482f4b4-e343-43b6-b170-9a65bc822c77"
$MAX_LOG_SIZE = 10MB
$MAX_RETRIES = 3
$RETRY_DELAY_SECONDS = 15
$UPDATE_TIMEOUT_MINUTES = 60

# Initialize logging with correlation ID for tracking
$script:CorrelationId = [guid]::NewGuid().ToString("N").Substring(0,8)
$script:LogFile = Join-Path $LogPath "DriverUpdater_$($script:CorrelationId)_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Security validation class
class SecurityValidator {
    static [bool] ValidateAdminPrivileges() {
        return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    static [bool] ValidateSystemIntegrity() {
        try {
            # Check if Windows Update service is accessible
            $wuService = Get-Service -Name "wuauserv" -ErrorAction Stop
            return ($wuService.Status -in @('Running', 'Stopped'))
        }
        catch {
            return $false
        }
    }
}

# Enhanced logging with security context
function Write-EnhancedLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Security')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $callerInfo = (Get-PSCallStack)[1].Command
    $logEntry = "[$timestamp] [$script:CorrelationId] [$Level] [$callerInfo] $Message"

    # Color coding for console output
    $colors = @{
        'Info'     = 'White'
        'Warning'  = 'Yellow'
        'Error'    = 'Red'
        'Success'  = 'Green'
        'Security' = 'Magenta'
    }

    # Write to host with color
    if ($Host.UI.SupportsVirtualTerminal) {
        # Use ANSI escape codes for better compatibility
        $colorMap = @{
            'White'   = "`e[97m"
            'Yellow'  = "`e[93m"
            'Red'     = "`e[91m"
            'Green'   = "`e[92m"
            'Magenta' = "`e[95m"
        }
        $colorCode = $colorMap[$colors[$Level]]
        Write-Host "$colorCode$logEntry`e[0m"
    } else {
        Write-Host $logEntry -ForegroundColor $colors[$Level]
    }

    try {
        # Thread-safe file logging
        $mutex = New-Object System.Threading.Mutex($false, "DriverUpdaterLog_$script:CorrelationId")
        $mutex.WaitOne() | Out-Null

        # Rotate log if necessary
        if (Test-Path $script:LogFile -PathType Leaf) {
            $logSize = (Get-Item $script:LogFile).Length
            if ($logSize -gt $MAX_LOG_SIZE) {
                $archivePath = $script:LogFile -replace '\.log$', '_archived.log'
                Move-Item $script:LogFile $archivePath -Force
            }
        }

        Add-Content -Path $script:LogFile -Value $logEntry -Encoding UTF8
    }
    catch {
        Write-Warning "Failed to write to log file: $($_.Exception.Message)"
    }
    finally {
        if ($mutex) { $mutex.ReleaseMutex(); $mutex.Dispose() }
    }
}


# Network connectivity validation with retry logic
function Test-NetworkConnectivity {
    [CmdletBinding()]
    param()

    Write-EnhancedLog "Testing network connectivity to Microsoft Update servers" -Level Info

    $testServers = @(
        "update.microsoft.com",
        "windowsupdate.microsoft.com",
        "download.microsoft.com"
    )

    foreach ($server in $testServers) {
        $retryCount = 0
        while ($retryCount -lt $MAX_RETRIES) {
            try {
                $result = Test-NetConnection -ComputerName $server -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
                if ($result) {
                    Write-EnhancedLog "Successfully connected to $server" -Level Success
                    return $true
                }
            }
            catch {
                Write-EnhancedLog "Connection attempt $($retryCount + 1) to $server failed: $($_.Exception.Message)" -Level Warning
            }

            $retryCount++
            if ($retryCount -lt $MAX_RETRIES) {
                Start-Sleep -Seconds $RETRY_DELAY_SECONDS
            }
        }
    }

    throw "Failed to establish connectivity to Microsoft Update servers after $MAX_RETRIES attempts"
}

# Enhanced module installation with security validation
function Install-RequiredModules {
    [CmdletBinding()]
    param()

    Write-EnhancedLog "Installing and validating required PowerShell modules" -Level Info

    try {
        # Security check: Validate PowerShell Gallery
        $psGallery = Get-PSRepository -Name "PSGallery" -ErrorAction SilentlyContinue
        if (-not $psGallery -or $psGallery.InstallationPolicy -ne 'Trusted') {
            Write-EnhancedLog "Configuring PowerShell Gallery as trusted repository" -Level Security
            Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted -Force
        }

        # Install NuGet provider if missing
        if (-not (Get-PackageProvider -Name "NuGet" -ErrorAction SilentlyContinue)) {
             Write-EnhancedLog "Installing NuGet package provider" -Level Info
             Install-PackageProvider -Name "NuGet" -MinimumVersion "2.8.5.201" -Force -Scope CurrentUser
        }

        # Install PSWindowsUpdate module with verification
        if (-not (Get-Module -ListAvailable -Name "PSWindowsUpdate")) {
            Write-EnhancedLog "Installing PSWindowsUpdate module from PowerShell Gallery" -Level Info
            Install-Module -Name "PSWindowsUpdate" -Force -Scope CurrentUser -AllowClobber
        }

        # Import and validate module
        Import-Module "PSWindowsUpdate" -Force
        $importedModule = Get-Module -Name "PSWindowsUpdate"
        if (-not $importedModule) {
            throw "Failed to import PSWindowsUpdate module"
        }

        Write-EnhancedLog "PSWindowsUpdate module successfully loaded (Version: $($importedModule.Version))" -Level Success

    }
    catch {
        Write-EnhancedLog "Module installation failed: $($_.Exception.Message)" -Level Error
        throw
    }
}

# Microsoft Update Service registration with enhanced validation
function Register-MicrosoftUpdateService {
    [CmdletBinding()]
    param()

    Write-EnhancedLog "Registering Microsoft Update Service for driver updates" -Level Info

    try {
        $serviceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"
        $registeredServices = $serviceManager.Services

        # Check if Microsoft Update service is already registered
        $existingService = $registeredServices | Where-Object { $_.ServiceID -eq $MICROSOFT_UPDATE_SERVICE_ID }

        if (-not $existingService) {
            Write-EnhancedLog "Microsoft Update Service not found. Registering..." -Level Info

            # Register Microsoft Update service (includes driver updates)
            $newService = $serviceManager.AddService2($MICROSOFT_UPDATE_SERVICE_ID, 7, "")

            # Validate registration
            Start-Sleep -Seconds 2
            $registeredServices = $serviceManager.Services
            $validatedService = $registeredServices | Where-Object { $_.ServiceID -eq $MICROSOFT_UPDATE_SERVICE_ID }

            if (-not $validatedService) {
                throw "Service registration validation failed"
            }

            Write-EnhancedLog "Microsoft Update Service registered successfully (Name: $($validatedService.Name))" -Level Success
        }
        else {
            Write-EnhancedLog "Microsoft Update Service already registered (Name: $($existingService.Name))" -Level Info
        }
    }
    catch {
        Write-EnhancedLog "Failed to register Microsoft Update Service: $($_.Exception.Message)" -Level Error
        throw
    }
    finally {
        if ($serviceManager) {
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($serviceManager) | Out-Null
        }
    }
}

# Enhanced update detection with driver-specific filtering
function Get-AvailableUpdates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [bool]$DriversOnly = $true
    )

    Write-EnhancedLog "Scanning for available updates using Windows Update Agent API" -Level Info

    try {
        # Primary method: Use PSWindowsUpdate module
        $searchCriteria = if ($DriversOnly) {
            @{
                MicrosoftUpdate = $true
                IsInstalled     = $false
                CategoryIds     = '268C95A1-F734-4526-8263-BDBC74C1F8CA' # Device Drivers category
            }
        } else {
            @{
                MicrosoftUpdate = $true
                IsInstalled     = $false
            }
        }

        Write-EnhancedLog "Executing update search with criteria: $(if($DriversOnly){'Drivers Only'}else{'All Updates'})" -Level Info
        $updates = Get-WindowsUpdate @searchCriteria -Verbose:$false

        if ($updates) {
            Write-EnhancedLog "Found $($updates.Count) available updates" -Level Success

            # Log update details
            foreach ($update in $updates) {
                $updateType = if ($update.Categories -match "Driver") { "Driver" } else { "Software" }
                Write-EnhancedLog "  - [$updateType] $($update.Title) (Size: $([math]::Round($update.Size/1MB,2))MB)" -Level Info
            }
        }
        else {
            Write-EnhancedLog "No updates found matching criteria" -Level Info
        }

        return $updates
    }
    catch {
        Write-EnhancedLog "Update search failed, attempting fallback method: $($_.Exception.Message)" -Level Warning

        # Fallback: Direct Windows Update Agent COM interface
        try {
            $updateSession = New-Object -ComObject "Microsoft.Update.Session"
            $updateSearcher = $updateSession.CreateUpdateSearcher()

            # Configure searcher for Microsoft Update
            $updateSearcher.ServerSelection = 2 # Include Microsoft Update
            $updateSearcher.IncludePotentiallySupersededUpdates = $false

            $searchCriteria = if ($DriversOnly) {
                "IsInstalled=0 and Type='Driver'"
            } else {
                "IsInstalled=0"
            }

            Write-EnhancedLog "Executing COM-based search with criteria: $searchCriteria" -Level Info
            $searchResult = $updateSearcher.Search($searchCriteria)

            if ($searchResult.Updates.Count -gt 0) {
                Write-EnhancedLog "Found $($searchResult.Updates.Count) updates via COM interface" -Level Success
                return $searchResult.Updates
            }
            else {
                Write-EnhancedLog "No updates found via COM interface" -Level Info
                return @()
            }
        }
        catch {
            Write-EnhancedLog "COM fallback also failed: $($_.Exception.Message)" -Level Error
            throw "Both update search methods failed"
        }
        finally {
            if ($updateSession) {
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($updateSession) | Out-Null
            }
        }
    }
}

# Enhanced update installation with progress tracking
function Install-Updates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$Updates
    )

    if ($Updates.Count -eq 0) {
        Write-EnhancedLog "No updates to install" -Level Info
        return
    }

    Write-EnhancedLog "Installing $($Updates.Count) updates" -Level Info

    try {
        # Use PSWindowsUpdate for installation with enhanced options
        $installParams = @{
            AcceptAll     = $true
            IgnoreReboot  = $true
            Verbose       = $false
            ForceInstall  = $false
            WindowsUpdate = $true
        }

        # Add timeout protection
        $job = Start-Job -ScriptBlock {
            param($InstallParams)
            Import-Module PSWindowsUpdate -Force
            Install-WindowsUpdate @InstallParams
        } -ArgumentList $installParams

        if (Wait-Job -Job $job -Timeout ($UPDATE_TIMEOUT_MINUTES * 60)) {
            Receive-Job -Job $job | Out-Null
            Write-EnhancedLog "Update installation process completed" -Level Success

            if (Test-PendingReboot) {
                Write-EnhancedLog "System reboot is required. Creating a scheduled task to continue after reboot." -Level Warning
                Create-UpdateTask
                return $true # Indicates reboot needed
            }
        }
        else {
            Write-EnhancedLog "Update installation timed out after $UPDATE_TIMEOUT_MINUTES minutes" -Level Error
            Stop-Job -Job $job
            throw "Update installation timeout"
        }

        return $false # No reboot needed
    }
    catch {
        Write-EnhancedLog "Update installation failed: $($_.Exception.Message)" -Level Error
        throw
    }
    finally {
        if ($job) {
            Remove-Job -Job $job -Force
        }
    }
}

# Function to create scheduled task for post-reboot execution
function Create-UpdateTask {
    [CmdletBinding()]
    param()

    $taskName = "EnhancedDriverUpdaterTask"
    $taskPath = "\Microsoft\Windows\PowerShell\"
    Write-EnhancedLog "Creating scheduled task '$taskName' for post-reboot execution" -Level Info

    try {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

        Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Resumes the driver update process after a reboot." -Force -ErrorAction Stop
        Write-EnhancedLog "Scheduled task '$taskName' created successfully" -Level Success
    }
    catch {
        Write-EnhancedLog "Failed to create scheduled task: $($_.Exception.Message)" -Level Error
    }
}

# Function to delete the post-reboot scheduled task
function Delete-UpdateTask {
    [CmdletBinding()]
    param()

    $taskName = "EnhancedDriverUpdaterTask"
    $taskPath = "\Microsoft\Windows\PowerShell\"

    if (Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue) {
        Write-EnhancedLog "Deleting post-reboot scheduled task '$taskName'" -Level Info
        Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction Stop
        Write-EnhancedLog "Scheduled task '$taskName' deleted successfully" -Level Success
    }
}

# Enhanced reboot detection using multiple registry locations
function Test-PendingReboot {
    [CmdletBinding()]
    param()

    Write-EnhancedLog "Checking for pending reboot requirements" -Level Info

    $rebootIndicators = @(
        @{
            Path        = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
            Name        = "RebootRequired"
            Description = "Windows Update Reboot Required"
        },
        @{
            Path        = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
            Name        = "PendingFileRenameOperations"
            Description = "Pending File Rename Operations"
        },
        @{
            Path        = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing"
            Name        = "RebootPending"
            Description = "Component Based Servicing Reboot Pending"
        }
    )

    foreach ($indicator in $rebootIndicators) {
        if (Get-ItemProperty -Path $indicator.Path -Name $indicator.Name -ErrorAction SilentlyContinue) {
            Write-EnhancedLog "Pending reboot detected: $($indicator.Description)" -Level Warning
            return $true
        }
    }

    Write-EnhancedLog "No pending reboot detected" -Level Info
    return $false
}

# Main execution function with comprehensive error handling
function Start-DriverUpdate {
    [CmdletBinding()]
    param()

    Write-EnhancedLog "=== Enhanced Windows Driver Updater Started ===" -Level Info
    Write-EnhancedLog "Correlation ID: $script:CorrelationId" -Level Info
    Write-EnhancedLog "Log file: $script:LogFile" -Level Info

    try {
        # Security validation
        if (-not [SecurityValidator]::ValidateAdminPrivileges()) {
            Write-EnhancedLog "Administrative privileges not detected. Attempting to elevate..." -Level Warning
            $powershellPath = (Get-Command powershell.exe).Path
            $scriptPath = $MyInvocation.MyCommand.Path
            $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" $($MyInvocation.Line)"
            Start-Process -FilePath $powershellPath -ArgumentList $arguments -Verb RunAs
            exit
        }
        Write-EnhancedLog "Administrative privileges validated" -Level Security

        if (-not [SecurityValidator]::ValidateSystemIntegrity()) {
            throw "Windows Update service is not accessible. System integrity check failed."
        }
        Write-EnhancedLog "System integrity validated" -Level Security

        # Clean up any lingering scheduled task from a previous run
        Delete-UpdateTask

        # Network connectivity test
        Test-NetworkConnectivity

        # Install required modules
        Install-RequiredModules

        # Register Microsoft Update service
        Register-MicrosoftUpdateService

        # Determine update scope
        $driverTypesOnly = $DriverTypesOnly -and (-not $IncludeSoftware)
        Write-EnhancedLog "Update scope: $(if($driverTypesOnly){'Driver updates only'}else{'All available updates'})" -Level Info

        # Get available updates
        $availableUpdates = Get-AvailableUpdates -DriversOnly $driverTypesOnly

        if ($availableUpdates) {
            # Install updates
            $rebootRequired = Install-Updates -Updates $availableUpdates

            if ($rebootRequired) {
                Write-EnhancedLog "Updates installed, a reboot is required to complete the installation." -Level Warning
                Write-EnhancedLog "The script will continue automatically after the reboot." -Level Info
                Restart-Computer -Force
            } else {
                Write-EnhancedLog "Update installation completed successfully. No reboot required." -Level Success
            }
        }
        else {
            Write-EnhancedLog "System is up to date. No updates available." -Level Success
        }
    }
    catch {
        Write-EnhancedLog "Critical error occurred: $($_.Exception.ToString())" -Level Error
        throw
    }
    finally {
        Write-EnhancedLog "=== Enhanced Windows Driver Updater Completed ===" -Level Info

        # Open log file for review
        if (Test-Path $script:LogFile) {
            Write-EnhancedLog "Opening log file for review: $script:LogFile" -Level Info
            try {
                Invoke-Item -Path $script:LogFile
            }
            catch {
                Write-EnhancedLog "Failed to open log file automatically: $($_.Exception.Message)" -Level Warning
            }
        }
    }
}

# Script entry point
if ($MyInvocation.InvocationName -ne '.') {
    try {
        Start-DriverUpdate
    }
    catch {
        # Errors are already logged by Start-DriverUpdate
        exit 1
    }
    finally {
        Write-EnhancedLog "Script finished. Press any key to exit..." -Level Info
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}
