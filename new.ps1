# WindowsComprehensiveUpdater.ps1
# Comprehensive Windows update script that installs ALL available updates

# Set execution policy for this session only
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force

# Define paths and constants
$scriptDir = $PSScriptRoot
$logFile = Join-Path -Path $scriptDir -ChildPath "WindowsUpdateLog.txt"
$stateFile = Join-Path -Path $scriptDir -ChildPath "UpdateState.json"
$lockFile = Join-Path -Path $scriptDir -ChildPath "UpdateScript.lock"

# Configuration Constants
$MICROSOFT_UPDATE_SERVICE_ID = "7971f918-a847-4430-9279-4a52d1efe18d"
$DRIVER_CATEGORY_ID = "E6CF1350-C01B-414D-A61F-263D14D133B4"  # Correct driver category GUID for Windows Update
$MAX_LOG_SIZE = 5MB
$MAX_RETRIES = 3
$MAX_REBOOT_CYCLES = 5  # Prevent infinite reboot loops
$RETRY_DELAY = 10
$INTERNET_CHECK_TIMEOUT = 5  # Seconds per server
$SFC_DISM_TIMEOUT_MINUTES = 30
$WINGET_EXCLUSIONS = @()  # Add package IDs to exclude from updates

# Script configuration
$script:correlationId = [guid]::NewGuid().ToString()
$global:ErrorActionPreference = 'Continue'  # Changed from Stop to Continue
$scriptStartTime = Get-Date
$script:isInteractive = [Environment]::UserInteractive -and [Environment]::GetCommandLineArgs() -notcontains '-NonInteractive'
$script:updateMode = "All"  # Default to ALL updates - Options: "Drivers", "Critical", "All"

# State management object
$script:state = @{
    CurrentPhase = "Initialization"
    RebootCount = 0
    CompletedSteps = @()
    FailedUpdates = @()
    SuccessfulUpdates = @()
    LastRunTime = $null
    CorrelationId = $script:correlationId
}

# Function to write to log with file locking
function Write-Log {
    param (
        [string]$Message,
        [string]$Severity = 'Info'
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Severity] $Message"

    # Display to console
    $color = switch($Severity) {
        'Error' { 'Red' }
        'Warning' { 'Yellow' }
        'Success' { 'Green' }
        default { 'White' }
    }
    Write-Host $logEntry -ForegroundColor $color

    # Write to file with retry logic
    $retries = 3
    while ($retries -gt 0) {
        try {
            # Rotate log if needed
            if (Test-Path $logFile -PathType Leaf) {
                $logSize = (Get-Item $logFile).Length
                if ($logSize -gt $MAX_LOG_SIZE) {
                    $archivePath = Join-Path $scriptDir "WindowsUpdateLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
                    Move-Item $logFile $archivePath -Force
                }
            }

            # Append to log file
            Add-Content -Path $logFile -Value "[$correlationId] $logEntry" -ErrorAction Stop
            break
        }
        catch {
            $retries--
            if ($retries -eq 0) {
                Write-Host "Failed to write to log file: $($_.Exception.Message)" -ForegroundColor Red
            }
            Start-Sleep -Milliseconds 100
        }
    }
}

# Function to manage script state
function Get-ScriptState {
    if (Test-Path $stateFile) {
        try {
            $content = Get-Content $stateFile -Raw | ConvertFrom-Json
            return $content
        }
        catch {
            Write-Log "Failed to load state file: $($_.Exception.Message)" -Severity 'Warning'
        }
    }
    return $script:state
}

function Save-ScriptState {
    try {
        $script:state.LastRunTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $script:state | ConvertTo-Json -Depth 10 | Set-Content $stateFile -Force
        Write-Log "State saved successfully" -Severity 'Info'
    }
    catch {
        Write-Log "Failed to save state: $($_.Exception.Message)" -Severity 'Error'
    }
}

function Clear-ScriptState {
    try {
        if (Test-Path $stateFile) {
            Remove-Item $stateFile -Force
            Write-Log "State file cleared" -Severity 'Info'
        }
    }
    catch {
        Write-Log "Failed to clear state file: $($_.Exception.Message)" -Severity 'Warning'
    }
}

# Function to prevent concurrent execution
function Set-ScriptLock {
    try {
        $lockContent = @{
            PID = $PID
            StartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            CorrelationId = $script:correlationId
        }
        $lockContent | ConvertTo-Json | Set-Content $lockFile -Force
        return $true
    }
    catch {
        return $false
    }
}

function Test-ScriptLock {
    if (Test-Path $lockFile) {
        try {
            $lock = Get-Content $lockFile -Raw | ConvertFrom-Json
            $process = Get-Process -Id $lock.PID -ErrorAction SilentlyContinue
            if ($process) {
                Write-Log "Another instance is running (PID: $($lock.PID))" -Severity 'Warning'
                return $true
            }
        }
        catch {
            # Lock file is invalid, remove it
            Remove-Item $lockFile -Force -ErrorAction SilentlyContinue
        }
    }
    return $false
}

function Remove-ScriptLock {
    try {
        if (Test-Path $lockFile) {
            Remove-Item $lockFile -Force
        }
    }
    catch {
        Write-Log "Failed to remove lock file: $($_.Exception.Message)" -Severity 'Warning'
    }
}

# Optimized internet check with timeout
function Check-Internet {
    Write-Log "Checking internet connectivity..." -Severity 'Info'

    $testUrls = @(
        "http://www.msftconnecttest.com/connecttest.txt",
        "http://www.google.com",
        "http://www.microsoft.com"
    )

    foreach ($url in $testUrls) {
        try {
            $request = [System.Net.HttpWebRequest]::Create($url)
            $request.Timeout = $INTERNET_CHECK_TIMEOUT * 1000
            $request.Method = "HEAD"
            $response = $request.GetResponse()
            $response.Close()
            Write-Log "Internet connection confirmed via $url" -Severity 'Info'
            return $true
        }
        catch {
            continue
        }
    }

    Write-Log "No internet connection available" -Severity 'Error'
    return $false
}

# Function to verify and load PSWindowsUpdate module
function Ensure-PSWindowsUpdateModule {
    try {
        # Check if module is already loaded
        if (Get-Module -Name PSWindowsUpdate) {
            return $true
        }

        # Try to import module
        Import-Module PSWindowsUpdate -Force -ErrorAction SilentlyContinue
        if (Get-Module -Name PSWindowsUpdate) {
            Write-Log "PSWindowsUpdate module loaded successfully" -Severity 'Info'
            return $true
        }

        # Module not available, try to install
        Write-Log "Installing PSWindowsUpdate module..." -Severity 'Info'

        # Ensure NuGet provider
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser
        }

        # Set PSGallery as trusted
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

        # Install module
        Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber

        # Import and verify
        Import-Module PSWindowsUpdate -Force
        if (Get-Module -Name PSWindowsUpdate) {
            Write-Log "PSWindowsUpdate module installed and loaded" -Severity 'Success'
            return $true
        }
    }
    catch {
        Write-Log "Failed to ensure PSWindowsUpdate module: $($_.Exception.Message)" -Severity 'Error'
    }
    return $false
}

# Function to register Microsoft Update Service
function Register-MicrosoftUpdateService {
    Write-Log "Registering Microsoft Update Service..." -Severity 'Info'
    $serviceManager = $null

    try {
        $serviceManager = New-Object -ComObject Microsoft.Update.ServiceManager
        $service = $serviceManager.Services | Where-Object { $_.ServiceID -eq $MICROSOFT_UPDATE_SERVICE_ID }

        if (-not $service) {
            Write-Log "Adding Microsoft Update Service..." -Severity 'Info'
            $serviceManager.AddService2($MICROSOFT_UPDATE_SERVICE_ID, 7, "")

            # Poll for service registration
            $timeout = 30
            $elapsed = 0
            while ($elapsed -lt $timeout) {
                Start-Sleep -Seconds 2
                $elapsed += 2
                $service = $serviceManager.Services | Where-Object { $_.ServiceID -eq $MICROSOFT_UPDATE_SERVICE_ID }
                if ($service) {
                    Write-Log "Microsoft Update Service registered successfully" -Severity 'Success'
                    return $true
                }
            }
            Write-Log "Timeout waiting for service registration" -Severity 'Warning'
        }
        else {
            Write-Log "Microsoft Update Service already registered" -Severity 'Info'
            return $true
        }
    }
    catch {
        Write-Log "Failed to register Microsoft Update Service: $($_.Exception.Message)" -Severity 'Error'
    }
    finally {
        if ($serviceManager) {
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($serviceManager) | Out-Null
        }
    }
    return $false
}

# Function to create scheduled task for post-reboot
function Create-UpdateTask {
    $taskName = "WindowsDriverUpdaterTask"

    try {
        # Check if task already exists
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Write-Log "Scheduled task already exists" -Severity 'Info'
            return $true
        }

        # Create task with proper security context
        $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' `
            -Argument "-NoProfile -ExecutionPolicy Bypass -NonInteractive -File `"$PSCommandPath`""

        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -RestartInterval (New-TimeSpan -Minutes 5) -RestartCount 3

        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings -Force | Out-Null

        Write-Log "Scheduled task created successfully" -Severity 'Success'
        return $true
    }
    catch {
        Write-Log "Failed to create scheduled task: $($_.Exception.Message)" -Severity 'Error'
        return $false
    }
}

# Function to delete scheduled task
function Delete-UpdateTask {
    $taskName = "WindowsDriverUpdaterTask"

    try {
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($task) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            Write-Log "Scheduled task removed" -Severity 'Info'
        }
    }
    catch {
        Write-Log "Failed to remove scheduled task: $($_.Exception.Message)" -Severity 'Warning'
    }
}

# Function to check for pending reboot
function Test-PendingReboot {
    $rebootRequired = $false

    # Check Windows Update specific keys only
    $updateKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    )

    foreach ($key in $updateKeys) {
        if (Test-Path $key) {
            Write-Log "Reboot required (Registry: $key)" -Severity 'Info'
            $rebootRequired = $true
            break
        }
    }

    return $rebootRequired
}

# Main Windows update function - installs ALL available updates
function Install-AllWindowsUpdates {
    Write-Log "Checking for ALL Windows updates..." -Severity 'Info'

    # Ensure module is loaded
    if (-not (Ensure-PSWindowsUpdateModule)) {
        Write-Log "PSWindowsUpdate module not available, using COM fallback" -Severity 'Warning'
        return Install-AllWindowsUpdatesViaCOM
    }

    try {
        # Get ALL available updates (not just drivers)
        Write-Log "Searching for ALL Windows updates using PSWindowsUpdate..." -Severity 'Info'
        $updates = Get-WindowsUpdate -MicrosoftUpdate -IsHidden $false -ErrorAction Stop

        if ($updates.Count -eq 0) {
            Write-Log "No Windows updates available" -Severity 'Info'
            return @{ Success = $true; RebootRequired = $false; UpdateCount = 0 }
        }

        Write-Log "Found $($updates.Count) Windows updates:" -Severity 'Info'
        foreach ($update in $updates) {
            $sizeInMB = if ($update.Size) { [math]::Round($update.Size / 1MB, 2) } else { "Unknown" }
            Write-Log "  - $($update.Title) (${sizeInMB}MB)" -Severity 'Info'
        }

        # Install updates one by one to track progress
        $successCount = 0
        $failCount = 0

        foreach ($update in $updates) {
            try {
                Write-Log "Installing: $($update.Title)" -Severity 'Info'
                $result = Install-WindowsUpdate -KBArticleID $update.KBArticleID -AcceptAll -IgnoreReboot -ErrorAction Stop

                if ($result.Result -eq "Installed") {
                    $successCount++
                    $script:state.SuccessfulUpdates += $update.Title
                    Write-Log "Successfully installed: $($update.Title)" -Severity 'Success'
                }
                else {
                    $failCount++
                    $script:state.FailedUpdates += $update.Title
                    Write-Log "Failed to install: $($update.Title)" -Severity 'Warning'
                }
            }
            catch {
                $failCount++
                $script:state.FailedUpdates += $update.Title
                Write-Log "Error installing $($update.Title): $($_.Exception.Message)" -Severity 'Error'
            }

            # Save state after each update
            Save-ScriptState
        }

        Write-Log "Windows update summary: $successCount succeeded, $failCount failed" -Severity 'Info'

        return @{
            Success = $true
            RebootRequired = Test-PendingReboot
            UpdateCount = $successCount
        }
    }
    catch {
        Write-Log "Error in PSWindowsUpdate method: $($_.Exception.Message)" -Severity 'Error'
        return Install-AllWindowsUpdatesViaCOM
    }
}

# Fallback COM-based Windows update function for ALL updates
function Install-AllWindowsUpdatesViaCOM {
    Write-Log "Using COM interface for ALL Windows updates..." -Severity 'Info'

    $updateSession = $null
    $updateSearcher = $null
    $updatesToInstall = $null
    $installer = $null

    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()

        # Search for ALL available updates (not just drivers)
        $searchCriteria = "IsInstalled=0 and IsHidden=0"
        Write-Log "Searching for ALL updates with criteria: $searchCriteria" -Severity 'Info'

        $searchResult = $updateSearcher.Search($searchCriteria)

        if ($searchResult.Updates.Count -eq 0) {
            Write-Log "No Windows updates found via COM" -Severity 'Info'
            return @{ Success = $true; RebootRequired = $false; UpdateCount = 0 }
        }

        Write-Log "Found $($searchResult.Updates.Count) Windows updates via COM" -Severity 'Info'

        $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($update in $searchResult.Updates) {
            $sizeInMB = [math]::Round($update.MaxDownloadSize / 1MB, 2)
            Write-Log "  - $($update.Title) (${sizeInMB}MB)" -Severity 'Info'
            $updatesToInstall.Add($update) | Out-Null
        }

        # Download updates
        Write-Log "Downloading Windows updates..." -Severity 'Info'
        $downloader = $updateSession.CreateUpdateDownloader()
        $downloader.Updates = $updatesToInstall
        $downloadResult = $downloader.Download()

        if ($downloadResult.ResultCode -ne 2) {
            Write-Log "Download failed with code: $($downloadResult.ResultCode)" -Severity 'Error'
            return @{ Success = $false; RebootRequired = $false; UpdateCount = 0 }
        }

        # Install updates
        Write-Log "Installing Windows updates..." -Severity 'Info'
        $installer = $updateSession.CreateUpdateInstaller()
        $installer.Updates = $updatesToInstall
        $installResult = $installer.Install()

        $resultMessage = switch ($installResult.ResultCode) {
            2 { "Succeeded" }
            3 { "Succeeded with Errors" }
            4 { "Failed" }
            5 { "Aborted" }
            default { "Unknown" }
        }

        Write-Log "Installation result: $resultMessage" -Severity 'Info'

        return @{
            Success = ($installResult.ResultCode -eq 2 -or $installResult.ResultCode -eq 3)
            RebootRequired = $installResult.RebootRequired
            UpdateCount = $updatesToInstall.Count
        }
    }
    catch {
        Write-Log "COM update failed: $($_.Exception.Message)" -Severity 'Error'
        return @{ Success = $false; RebootRequired = $false; UpdateCount = 0 }
    }
    finally {
        # Clean up COM objects
        if ($installer) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($installer) | Out-Null }
        if ($updatesToInstall) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($updatesToInstall) | Out-Null }
        if ($updateSearcher) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($updateSearcher) | Out-Null }
        if ($updateSession) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($updateSession) | Out-Null }
    }
}

# Function to categorize and log update types
function Get-UpdateCategories {
    param($updates)

    $categories = @{
        Security = @()
        Critical = @()
        Drivers = @()
        FeaturePacks = @()
        QualityUpdates = @()
        Other = @()
    }

    foreach ($update in $updates) {
        if ($update.Categories -match "Security") { $categories.Security += $update }
        elseif ($update.Categories -match "Critical") { $categories.Critical += $update }
        elseif ($update.Categories -match "Drivers") { $categories.Drivers += $update }
        elseif ($update.Categories -match "Feature") { $categories.FeaturePacks += $update }
        elseif ($update.Categories -match "Quality|Rollup") { $categories.QualityUpdates += $update }
        else { $categories.Other += $update }
    }

    Write-Log "Update breakdown:" -Severity 'Info'
    Write-Log "  Security: $($categories.Security.Count)" -Severity 'Info'
    Write-Log "  Critical: $($categories.Critical.Count)" -Severity 'Info'
    Write-Log "  Drivers: $($categories.Drivers.Count)" -Severity 'Info'
    Write-Log "  Feature Packs: $($categories.FeaturePacks.Count)" -Severity 'Info'
    Write-Log "  Quality Updates: $($categories.QualityUpdates.Count)" -Severity 'Info'
    Write-Log "  Other: $($categories.Other.Count)" -Severity 'Info'

    return $categories
}

# Selective WinGet update function
function Update-WinGetPackages {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Log "WinGet not available" -Severity 'Info'
        return
    }

    try {
        Write-Log "Checking WinGet packages..." -Severity 'Info'

        # Get list of available updates
        $updates = winget upgrade --accept-source-agreements 2>&1
        $updateList = $updates | Select-String -Pattern "^\S+\s+\S+\s+->\s+\S+" | ForEach-Object {
            $parts = $_.Line -split '\s+'
            $parts[0]  # Package ID
        }

        if ($updateList.Count -eq 0) {
            Write-Log "No WinGet updates available" -Severity 'Info'
            return
        }

        # Filter out excluded packages
        $toUpdate = $updateList | Where-Object { $_ -notin $WINGET_EXCLUSIONS }

        if ($toUpdate.Count -eq 0) {
            Write-Log "All available updates are excluded" -Severity 'Info'
            return
        }

        Write-Log "Updating $($toUpdate.Count) WinGet packages..." -Severity 'Info'

        foreach ($package in $toUpdate) {
            try {
                Write-Log "Updating: $package" -Severity 'Info'
                winget upgrade $package --silent --accept-package-agreements --accept-source-agreements
            }
            catch {
                Write-Log "Failed to update $package : $($_.Exception.Message)" -Severity 'Warning'
            }
        }
    }
    catch {
        Write-Log "WinGet update error: $($_.Exception.Message)" -Severity 'Warning'
    }
}

# Run system integrity check with timeout
function Invoke-SystemIntegrityCheck {
    if ($script:updateMode -ne "All") {
        return
    }

    Write-Log "Running system integrity checks (timeout: $SFC_DISM_TIMEOUT_MINUTES minutes)..." -Severity 'Info'

    # Run SFC with timeout
    try {
        $sfcJob = Start-Job -ScriptBlock {
            sfc /scannow
        }

        if (Wait-Job -Job $sfcJob -Timeout ($SFC_DISM_TIMEOUT_MINUTES * 60)) {
            $result = Receive-Job -Job $sfcJob
            Write-Log "SFC scan completed" -Severity 'Success'
        }
        else {
            Stop-Job -Job $sfcJob
            Write-Log "SFC scan timed out after $SFC_DISM_TIMEOUT_MINUTES minutes" -Severity 'Warning'
        }
        Remove-Job -Job $sfcJob -Force
    }
    catch {
        Write-Log "SFC scan error: $($_.Exception.Message)" -Severity 'Warning'
    }

    # Run DISM with timeout
    try {
        $dismJob = Start-Job -ScriptBlock {
            DISM /Online /Cleanup-Image /RestoreHealth
        }

        if (Wait-Job -Job $dismJob -Timeout ($SFC_DISM_TIMEOUT_MINUTES * 60)) {
            $result = Receive-Job -Job $dismJob
            Write-Log "DISM scan completed" -Severity 'Success'
        }
        else {
            Stop-Job -Job $dismJob
            Write-Log "DISM scan timed out after $SFC_DISM_TIMEOUT_MINUTES minutes" -Severity 'Warning'
        }
        Remove-Job -Job $dismJob -Force
    }
    catch {
        Write-Log "DISM scan error: $($_.Exception.Message)" -Severity 'Warning'
    }
}

# Function to handle reboot with state preservation
function Invoke-SafeReboot {
    Write-Log "Preparing for system reboot..." -Severity 'Info'

    # Increment reboot count
    $script:state.RebootCount++

    # Check if we've exceeded max reboots
    if ($script:state.RebootCount -ge $MAX_REBOOT_CYCLES) {
        Write-Log "Maximum reboot cycles ($MAX_REBOOT_CYCLES) reached. Stopping to prevent loop." -Severity 'Error'
        Clear-ScriptState
        Delete-UpdateTask
        return $false
    }

    # Save current state
    Save-ScriptState

    # Ensure scheduled task exists
    if (-not (Create-UpdateTask)) {
        Write-Log "Failed to create scheduled task for post-reboot" -Severity 'Error'
        return $false
    }

    Write-Log "Rebooting system (Reboot $($script:state.RebootCount) of $MAX_REBOOT_CYCLES)..." -Severity 'Info'

    # Remove lock file before reboot
    Remove-ScriptLock

    # Initiate reboot
    Restart-Computer -Force
    exit 0
}

# Dynamic progress tracking
function Show-Progress {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$CurrentStep,
        [int]$TotalSteps
    )

    if ($TotalSteps -gt 0) {
        $percentComplete = [math]::Round(($CurrentStep / $TotalSteps) * 100)
        Write-Progress -Activity $Activity -Status $Status -PercentComplete $percentComplete
        Write-Log "$Status ($percentComplete%)" -Severity 'Info'
    }
    else {
        Write-Progress -Activity $Activity -Status $Status
        Write-Log $Status -Severity 'Info'
    }
}

# Main execution wrapper with proper cleanup
function Invoke-MainExecution {
    $steps = @()

    # Build dynamic step list based on configuration
    $steps += "Check Prerequisites"
    $steps += "Internet Connectivity"

    if ($script:state.CurrentPhase -ne "PostReboot") {
        $steps += "Module Installation"
        $steps += "Service Registration"
    }

    $steps += "Windows Updates"


    if ($script:updateMode -eq "All") {
        $steps += "WinGet Updates"
        $steps += "System Integrity"
    }

    $totalSteps = $steps.Count
    $currentStep = 0

    try {
        # Step: Prerequisites
        $currentStep++
        Show-Progress -Activity "Windows Update Process" -Status "Checking prerequisites" `
            -CurrentStep $currentStep -TotalSteps $totalSteps

        # Check for admin privileges (already done before this function)
        Write-Log "Administrative privileges confirmed" -Severity 'Info'

        # Step: Internet connectivity
        $currentStep++
        Show-Progress -Activity "Windows Update Process" -Status "Checking internet connection" `
            -CurrentStep $currentStep -TotalSteps $totalSteps

        if (-not (Check-Internet)) {
            throw "No internet connection available"
        }

        # Step: Module installation (skip if post-reboot)
        if ($script:state.CurrentPhase -ne "PostReboot") {
            $currentStep++
            Show-Progress -Activity "Windows Update Process" -Status "Installing required modules" `
                -CurrentStep $currentStep -TotalSteps $totalSteps

            Ensure-PSWindowsUpdateModule | Out-Null
        }

        # Step: Service registration (skip if post-reboot)
        if ($script:state.CurrentPhase -ne "PostReboot") {
            $currentStep++
            Show-Progress -Activity "Windows Update Process" -Status "Registering update services" `
                -CurrentStep $currentStep -TotalSteps $totalSteps

            Register-MicrosoftUpdateService | Out-Null
        }

        # Step: Windows updates (ALL updates)
        $currentStep++
        Show-Progress -Activity "Windows Update Process" -Status "Installing ALL Windows updates" `
            -CurrentStep $currentStep -TotalSteps $totalSteps

        $updateResult = Install-AllWindowsUpdates

        if ($updateResult.RebootRequired) {
            Write-Log "Reboot required after Windows updates" -Severity 'Info'
            Invoke-SafeReboot
            return
        }

        # Step: Critical updates (if configured)
        # Critical updates are already included in Install-AllWindowsUpdates when updateMode is "All"

        # Step: WinGet updates (if configured)
        if ($script:updateMode -eq "All") {
            $currentStep++
            Show-Progress -Activity "Windows Update Process" -Status "Updating applications" `
                -CurrentStep $currentStep -TotalSteps $totalSteps

            Update-WinGetPackages
        }

        # Step: System integrity (if configured)
        if ($script:updateMode -eq "All") {
            $currentStep++
            Show-Progress -Activity "Windows Update Process" -Status "Running system integrity checks" `
                -CurrentStep $currentStep -TotalSteps $totalSteps

            Invoke-SystemIntegrityCheck
        }

        # Complete
        Write-Progress -Activity "Windows Update Process" -Completed
        Write-Log "=== Update Process Completed Successfully ===" -Severity 'Success'

        # Show summary
        Write-Log "`nUpdate Summary:" -Severity 'Info'
        Write-Log "  Successful Updates: $($script:state.SuccessfulUpdates.Count)" -Severity 'Info'
        Write-Log "  Failed Updates: $($script:state.FailedUpdates.Count)" -Severity 'Info'
        Write-Log "  Reboot Cycles: $($script:state.RebootCount)" -Severity 'Info'

        # Clean up
        Clear-ScriptState
        Delete-UpdateTask
    }
    catch {
        Write-Log "Critical error: $($_.Exception.Message)" -Severity 'Error'
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Severity 'Error'
        Save-ScriptState
    }
    finally {
        Write-Progress -Activity "Windows Update Process" -Completed
        Remove-ScriptLock
    }
}

# Function to play Darude Sandstorm beep pattern
function Invoke-DarudeSandstorm {
    # Darude Sandstorm beat pattern using console beeps
    # Frequency and duration to recreate the iconic rhythm
    $beepPattern = @(
        @{Freq=440; Dur=100}, @{Freq=440; Dur=100}, @{Freq=440; Dur=100}, @{Freq=440; Dur=100},
        @{Freq=392; Dur=100}, @{Freq=392; Dur=100}, @{Freq=392; Dur=100}, @{Freq=392; Dur=100},
        @{Freq=349; Dur=100}, @{Freq=349; Dur=100}, @{Freq=349; Dur=100}, @{Freq=349; Dur=100},
        @{Freq=440; Dur=50}, @{Freq=440; Dur=50}, @{Freq=523; Dur=200},
        @{Freq=440; Dur=100}, @{Freq=440; Dur=100}, @{Freq=440; Dur=100}, @{Freq=440; Dur=100}
    )

    Write-Host "`n🎵 DARUDE SANDSTORM - USER ACTION REQUIRED! 🎵" -ForegroundColor Magenta

    foreach ($beep in $beepPattern) {
        try {
            [Console]::Beep($beep.Freq, $beep.Dur)
        }
        catch {
            # If beep fails, use system sound
            [System.Media.SystemSounds]::Exclamation.Play()
            break
        }
    }
}

# Check for admin privileges BEFORE any operations
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Invoke-DarudeSandstorm  # Play Darude Sandstorm for UAC prompt
    Write-Host "Script requires administrator privileges. Relaunching as administrator..." -ForegroundColor Yellow
    Write-Host "Please approve the User Account Control (UAC) prompt." -ForegroundColor Cyan

    try {
        $arguments = "-NoProfile -ExecutionPolicy Bypass -NonInteractive -File `"$PSCommandPath`""
        Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -Verb RunAs -ErrorAction Stop
        exit
    }
    catch {
        Write-Host "`nFailed to elevate privileges: $($_.Exception.Message)" -ForegroundColor Red

        if ($script:isInteractive) {
            Write-Host "`nPress any key to exit..." -ForegroundColor Cyan
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        exit 1
    }
}

# Main script execution
try {
    Write-Log "=== Windows Comprehensive Updater Started ===" -Severity 'Info'
    Write-Log "Correlation ID: $($script:correlationId)" -Severity 'Info'
    Write-Log "Update Mode: $($script:updateMode)" -Severity 'Info'
    Write-Log "Interactive Mode: $($script:isInteractive)" -Severity 'Info'

    # Check for concurrent execution
    if (Test-ScriptLock) {
        Write-Log "Another instance is already running. Exiting." -Severity 'Warning'
        exit 0
    }

    # Set lock
    Set-ScriptLock | Out-Null

    # Load previous state if exists
    $previousState = Get-ScriptState
    if ($previousState.RebootCount -gt 0) {
        Write-Log "Resuming after reboot (Reboot count: $($previousState.RebootCount))" -Severity 'Info'
        $script:state = $previousState
        $script:state.CurrentPhase = "PostReboot"
    }

    # Execute main logic
    Invoke-MainExecution
}
catch {
    Write-Log "=== FATAL ERROR ===" -Severity 'Error'
    Write-Log "Error: $($_.Exception.Message)" -Severity 'Error'
    Write-Log "Stack: $($_.ScriptStackTrace)" -Severity 'Error'
}
finally {
    Remove-ScriptLock

    $executionTime = [math]::Round(((Get-Date) - $scriptStartTime).TotalMinutes, 2)
    Write-Log "Execution time: $executionTime minutes" -Severity 'Info'
    Write-Log "Log file: $logFile" -Severity 'Info'

    # Only prompt if interactive and not scheduled task
    if ($script:isInteractive -and -not $env:TASK_SCHEDULER) {
        Invoke-DarudeSandstorm  # Play Darude Sandstorm when waiting for user
        Write-Host "`nPress any key to exit..." -ForegroundColor Cyan
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}