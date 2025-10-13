# WindowsComprehensiveUpdater.ps1 - Enhanced Version with Fail-Safe Mechanisms
# Comprehensive Windows update script that installs ALL available updates with robust troubleshooting

# Set execution policy for this session only
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force

# Define paths and constants
$scriptDir = $PSScriptRoot
$logFile = Join-Path -Path $scriptDir -ChildPath "WindowsUpdateLog.txt"
$stateFile = Join-Path -Path $scriptDir -ChildPath "UpdateState.json"
$lockFile = Join-Path -Path $scriptDir -ChildPath "UpdateScript.lock"
$diagnosticLogFile = Join-Path -Path $scriptDir -ChildPath "DiagnosticReport.txt"

# Configuration Constants
$MICROSOFT_UPDATE_SERVICE_ID = "7971f918-a847-4430-9279-4a52d1efe18d"
$DRIVER_CATEGORY_ID = "E6CF1350-C01B-414D-A61F-263D14D133B4"
$MAX_LOG_SIZE = 5MB
$MAX_RETRIES = 5
$MAX_REBOOT_CYCLES = 5
$RETRY_DELAY = 15
$INTERNET_CHECK_TIMEOUT = 5
$WINGET_EXCLUSIONS = @()

# Official Microsoft Documentation Links
$script:MSDocLinks = @{
    WindowsUpdate = "https://support.microsoft.com/windows/update-windows-3c5ae7fc-9fb6-9af1-1984-b5e0412c556a"
    TroubleshootUpdate = "https://support.microsoft.com/windows/troubleshoot-problems-updating-windows-188c2b0f-10a7-d72f-65b8-32d177eb136c"
    DriverUpdate = "https://support.microsoft.com/windows/update-drivers-manually-in-windows-ec62f46c-ff14-c91d-eead-d7126dc1f7b6"
    WindowsUpdateService = "https://learn.microsoft.com/windows/deployment/update/windows-update-overview"
    ErrorCodes = "https://learn.microsoft.com/windows/deployment/update/windows-update-error-reference"
    DISM = "https://learn.microsoft.com/windows-hardware/manufacture/desktop/dism---deployment-image-servicing-and-management-technical-reference-for-windows"
    SFC = "https://support.microsoft.com/topic/use-the-system-file-checker-tool-to-repair-missing-or-corrupted-system-files-79aa86cb-ca52-166a-92a3-966e85d4094e"
}

# Common Windows Update Error Codes with Solutions
$script:UpdateErrorCodes = @{
    "0x80070002" = @{
        Description = "File or directory not found"
        Solution = "Run Windows Update Troubleshooter, check disk space"
        MSLink = "https://support.microsoft.com/kb/971058"
    }
    "0x80070003" = @{
        Description = "Path not found"
        Solution = "Clear Windows Update cache: net stop wuauserv, delete C:\Windows\SoftwareDistribution\Download\*, net start wuauserv"
        MSLink = "https://support.microsoft.com/kb/971058"
    }
    "0x8024402F" = @{
        Description = "Connection timeout"
        Solution = "Check firewall settings, verify internet connectivity, check proxy configuration"
        MSLink = "https://support.microsoft.com/kb/2732284"
    }
    "0x80244019" = @{
        Description = "Download failed"
        Solution = "Clear Windows Update cache, check network stability"
        MSLink = "https://support.microsoft.com/kb/2732284"
    }
    "0x80240034" = @{
        Description = "Broken update file"
        Solution = "Run DISM /Online /Cleanup-Image /RestoreHealth, then retry"
        MSLink = "https://support.microsoft.com/kb/947821"
    }
    "0x8007000E" = @{
        Description = "Out of memory"
        Solution = "Close applications, increase virtual memory, check for memory leaks"
        MSLink = "https://support.microsoft.com/kb/2970908"
    }
    "0x80070422" = @{
        Description = "Windows Update service disabled"
        Solution = "Enable Windows Update service: sc config wuauserv start=auto && net start wuauserv"
        MSLink = "https://support.microsoft.com/kb/2958012"
    }
}

# Script configuration
$script:correlationId = [guid]::NewGuid().ToString()
$global:ErrorActionPreference = 'Continue'
$scriptStartTime = Get-Date
$script:isInteractive = [Environment]::UserInteractive -and [Environment]::GetCommandLineArgs() -notcontains '-NonInteractive'
$script:updateMode = "All"

# State management object
$script:state = @{
    CurrentPhase = "Initialization"
    RebootCount = 0
    CompletedSteps = @()
    FailedUpdates = @()
    SuccessfulUpdates = @()
    LastRunTime = $null
    CorrelationId = $script:correlationId
    DiagnosticInfo = @{}
}

#region Logging and Diagnostics

function Write-Log {
    param (
        [string]$Message,
        [string]$Severity = 'Info'
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Severity] $Message"

    $color = switch($Severity) {
        'Error' { 'Red' }
        'Warning' { 'Yellow' }
        'Success' { 'Green' }
        'Info' { 'White' }
        'Debug' { 'Gray' }
        default { 'White' }
    }
    Write-Host $logEntry -ForegroundColor $color

    $retries = 3
    while ($retries -gt 0) {
        try {
            if (Test-Path $logFile -PathType Leaf) {
                $logSize = (Get-Item $logFile).Length
                if ($logSize -gt $MAX_LOG_SIZE) {
                    $archivePath = Join-Path $scriptDir "WindowsUpdateLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
                    Move-Item $logFile $archivePath -Force
                }
            }
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

function Write-DiagnosticReport {
    param([string]$Section, [hashtable]$Data)

    try {
        $report = "`n=== $Section - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===`n"
        foreach ($key in $Data.Keys) {
            $report += "$key : $($Data[$key])`n"
        }
        Add-Content -Path $diagnosticLogFile -Value $report -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log "Failed to write diagnostic report: $($_.Exception.Message)" -Severity 'Warning'
    }
}

function Get-WindowsUpdateErrorInfo {
    param([string]$ErrorCode)

    if ($script:UpdateErrorCodes.ContainsKey($ErrorCode)) {
        $errorInfo = $script:UpdateErrorCodes[$ErrorCode]
        Write-Log "Error Code: $ErrorCode" -Severity 'Error'
        Write-Log "  Description: $($errorInfo.Description)" -Severity 'Error'
        Write-Log "  Solution: $($errorInfo.Solution)" -Severity 'Info'
        Write-Log "  Microsoft KB: $($errorInfo.MSLink)" -Severity 'Info'
        return $errorInfo
    }
    else {
        Write-Log "Unknown error code: $ErrorCode" -Severity 'Error'
        Write-Log "  For more information, visit: $($script:MSDocLinks.ErrorCodes)" -Severity 'Info'
        return $null
    }
}

#endregion

#region State Management

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
        Write-Log "State saved successfully" -Severity 'Debug'
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

#endregion

#region System Diagnostics

function Test-SystemHealth {
    Write-Log "Running comprehensive system health diagnostics..." -Severity 'Info'
    $healthReport = @{}

    # Check disk space
    try {
        $systemDrive = $env:SystemDrive
        $drive = Get-PSDrive -Name $systemDrive.TrimEnd(':') -ErrorAction Stop
        $freeSpaceGB = [math]::Round($drive.Free / 1GB, 2)
        $healthReport.DiskSpaceFree = "$freeSpaceGB GB"

        if ($freeSpaceGB -lt 10) {
            Write-Log "WARNING: Low disk space ($freeSpaceGB GB). Recommend at least 10GB free" -Severity 'Warning'
            Write-Log "Solution: Clean up disk space using Disk Cleanup or Storage Sense" -Severity 'Info'
            $healthReport.DiskSpaceStatus = "LOW"
        }
        else {
            $healthReport.DiskSpaceStatus = "OK"
        }
    }
    catch {
        Write-Log "Failed to check disk space: $($_.Exception.Message)" -Severity 'Warning'
        $healthReport.DiskSpaceStatus = "UNKNOWN"
    }

    # Check memory
    try {
        $memory = Get-CimInstance -ClassName Win32_OperatingSystem
        $freeMemoryGB = [math]::Round($memory.FreePhysicalMemory / 1MB, 2)
        $totalMemoryGB = [math]::Round($memory.TotalVisibleMemorySize / 1MB, 2)
        $healthReport.MemoryFree = "$freeMemoryGB GB / $totalMemoryGB GB"

        if ($freeMemoryGB -lt 1) {
            Write-Log "WARNING: Low memory ($freeMemoryGB GB free)" -Severity 'Warning'
            $healthReport.MemoryStatus = "LOW"
        }
        else {
            $healthReport.MemoryStatus = "OK"
        }
    }
    catch {
        Write-Log "Failed to check memory: $($_.Exception.Message)" -Severity 'Warning'
        $healthReport.MemoryStatus = "UNKNOWN"
    }

    # Check Windows Update Service
    try {
        $wuService = Get-Service -Name wuauserv -ErrorAction Stop
        $healthReport.WindowsUpdateService = $wuService.Status

        if ($wuService.Status -ne 'Running') {
            Write-Log "Windows Update service is $($wuService.Status). Attempting to start..." -Severity 'Warning'
            Start-Service -Name wuauserv -ErrorAction Stop
            Write-Log "Windows Update service started successfully" -Severity 'Success'
            $healthReport.WindowsUpdateServiceFixed = $true
        }
    }
    catch {
        Write-Log "Windows Update service issue: $($_.Exception.Message)" -Severity 'Error'
        Write-Log "Solution: Run 'sc config wuauserv start=auto' and 'net start wuauserv' as admin" -Severity 'Info'
        Write-Log "Reference: $($script:MSDocLinks.TroubleshootUpdate)" -Severity 'Info'
        $healthReport.WindowsUpdateService = "ERROR"
    }

    # Check BITS Service
    try {
        $bitsService = Get-Service -Name BITS -ErrorAction Stop
        $healthReport.BITSService = $bitsService.Status

        if ($bitsService.Status -ne 'Running') {
            Write-Log "BITS service is $($bitsService.Status). Attempting to start..." -Severity 'Warning'
            Start-Service -Name BITS -ErrorAction Stop
            Write-Log "BITS service started successfully" -Severity 'Success'
            $healthReport.BITSServiceFixed = $true
        }
    }
    catch {
        Write-Log "BITS service issue: $($_.Exception.Message)" -Severity 'Error'
        $healthReport.BITSService = "ERROR"
    }

    # Check Cryptographic Services
    try {
        $cryptSvc = Get-Service -Name CryptSvc -ErrorAction Stop
        $healthReport.CryptographicService = $cryptSvc.Status

        if ($cryptSvc.Status -ne 'Running') {
            Write-Log "Cryptographic service is $($cryptSvc.Status). Attempting to start..." -Severity 'Warning'
            Start-Service -Name CryptSvc -ErrorAction Stop
            Write-Log "Cryptographic service started successfully" -Severity 'Success'
            $healthReport.CryptographicServiceFixed = $true
        }
    }
    catch {
        Write-Log "Cryptographic service issue: $($_.Exception.Message)" -Severity 'Error'
        $healthReport.CryptographicService = "ERROR"
    }

    # Check Windows version
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $healthReport.WindowsVersion = "$($osInfo.Caption) Build $($osInfo.BuildNumber)"
        $healthReport.OSArchitecture = $osInfo.OSArchitecture
        Write-Log "System: $($healthReport.WindowsVersion) ($($healthReport.OSArchitecture))" -Severity 'Info'
    }
    catch {
        Write-Log "Failed to get Windows version: $($_.Exception.Message)" -Severity 'Warning'
    }

    # Check pending file operations
    try {
        $pendingFileRename = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($pendingFileRename) {
            Write-Log "Pending file operations detected - reboot may be required" -Severity 'Warning'
            $healthReport.PendingFileOperations = $true
        }
        else {
            $healthReport.PendingFileOperations = $false
        }
    }
    catch {
        $healthReport.PendingFileOperations = "UNKNOWN"
    }

    Write-DiagnosticReport -Section "System Health Check" -Data $healthReport
    $script:state.DiagnosticInfo = $healthReport

    return $healthReport
}

function Repair-WindowsUpdateComponents {
    Write-Log "Attempting to repair Windows Update components..." -Severity 'Info'
    Write-Log "Reference: $($script:MSDocLinks.TroubleshootUpdate)" -Severity 'Info'

    $repairSuccess = $true

    try {
        # Stop Windows Update services
        Write-Log "Stopping Windows Update services..." -Severity 'Info'
        Stop-Service -Name wuauserv, BITS, CryptSvc -Force -ErrorAction SilentlyContinue

        # Clear Windows Update cache
        Write-Log "Clearing Windows Update cache..." -Severity 'Info'
        $updateCachePath = "$env:SystemRoot\SoftwareDistribution\Download"
        if (Test-Path $updateCachePath) {
            Remove-Item -Path "$updateCachePath\*" -Recurse -Force -ErrorAction SilentlyContinue
        }

        # Re-register DLLs
        Write-Log "Re-registering Windows Update DLLs..." -Severity 'Info'
        $dlls = @('atl.dll', 'urlmon.dll', 'mshtml.dll', 'shdocvw.dll', 'browseui.dll',
                  'jscript.dll', 'vbscript.dll', 'scrrun.dll', 'msxml.dll', 'msxml3.dll',
                  'msxml6.dll', 'actxprxy.dll', 'softpub.dll', 'wintrust.dll', 'dssenh.dll',
                  'rsaenh.dll', 'gpkcsp.dll', 'sccbase.dll', 'slbcsp.dll', 'cryptdlg.dll',
                  'oleaut32.dll', 'ole32.dll', 'shell32.dll', 'initpki.dll', 'wuapi.dll',
                  'wuaueng.dll', 'wuaueng1.dll', 'wucltui.dll', 'wups.dll', 'wups2.dll',
                  'wuweb.dll', 'qmgr.dll', 'qmgrprxy.dll', 'wucltux.dll', 'muweb.dll', 'wuwebv.dll')

        foreach ($dll in $dlls) {
            Start-Process -FilePath "regsvr32.exe" -ArgumentList "/s $dll" -Wait -NoNewWindow -ErrorAction SilentlyContinue
        }

        # Restart services
        Write-Log "Restarting Windows Update services..." -Severity 'Info'
        Start-Service -Name wuauserv, BITS, CryptSvc -ErrorAction Stop

        Write-Log "Windows Update component repair completed" -Severity 'Success'
    }
    catch {
        Write-Log "Failed to repair Windows Update components: $($_.Exception.Message)" -Severity 'Error'
        Write-Log "Consider running Windows Update Troubleshooter from Settings" -Severity 'Info'
        $repairSuccess = $false
    }

    return $repairSuccess
}

#endregion

#region Internet Connectivity

function Check-Internet {
    Write-Log "Checking internet connectivity..." -Severity 'Info'

    $testUrls = @(
        @{Url="http://www.msftconnecttest.com/connecttest.txt"; Name="Microsoft Connectivity Test"},
        @{Url="http://update.microsoft.com"; Name="Windows Update Server"},
        @{Url="http://windowsupdate.microsoft.com"; Name="Windows Update Mirror"},
        @{Url="http://www.google.com"; Name="Google DNS"},
        @{Url="http://www.cloudflare.com"; Name="Cloudflare"}
    )

    $successfulTests = 0
    foreach ($test in $testUrls) {
        try {
            $request = [System.Net.HttpWebRequest]::Create($test.Url)
            $request.Timeout = $INTERNET_CHECK_TIMEOUT * 1000
            $request.Method = "HEAD"
            $response = $request.GetResponse()
            $response.Close()
            Write-Log "  ✓ $($test.Name) - OK" -Severity 'Success'
            $successfulTests++

            if ($successfulTests -ge 2) {
                Write-Log "Internet connection verified" -Severity 'Success'
                return $true
            }
        }
        catch {
            Write-Log "  ✗ $($test.Name) - Failed" -Severity 'Warning'
            continue
        }
    }

    Write-Log "No internet connection available" -Severity 'Error'
    Write-Log "Troubleshooting steps:" -Severity 'Info'
    Write-Log "  1. Check network cable/Wi-Fi connection" -Severity 'Info'
    Write-Log "  2. Verify firewall settings" -Severity 'Info'
    Write-Log "  3. Check proxy configuration" -Severity 'Info'
    Write-Log "  4. Run: ipconfig /flushdns" -Severity 'Info'
    Write-Log "Reference: $($script:MSDocLinks.TroubleshootUpdate)" -Severity 'Info'
    return $false
}

#endregion

#region Module Management

function Ensure-PSWindowsUpdateModule {
    try {
        if (Get-Module -Name PSWindowsUpdate) {
            return $true
        }

        Import-Module PSWindowsUpdate -Force -ErrorAction SilentlyContinue
        if (Get-Module -Name PSWindowsUpdate) {
            Write-Log "PSWindowsUpdate module loaded successfully" -Severity 'Success'
            return $true
        }

        Write-Log "Installing PSWindowsUpdate module..." -Severity 'Info'

        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Write-Log "Installing NuGet package provider..." -Severity 'Info'
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser
        }

        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

        Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber

        Import-Module PSWindowsUpdate -Force
        if (Get-Module -Name PSWindowsUpdate) {
            Write-Log "PSWindowsUpdate module installed and loaded" -Severity 'Success'
            return $true
        }
    }
    catch {
        Write-Log "Failed to ensure PSWindowsUpdate module: $($_.Exception.Message)" -Severity 'Error'
        Write-Log "Falling back to COM interface" -Severity 'Warning'
    }
    return $false
}

#endregion

#region Update Services

function Register-MicrosoftUpdateService {
    Write-Log "Registering Microsoft Update Service (includes third-party updates)..." -Severity 'Info'
    $serviceManager = $null

    try {
        $serviceManager = New-Object -ComObject Microsoft.Update.ServiceManager
        $service = $serviceManager.Services | Where-Object { $_.ServiceID -eq $MICROSOFT_UPDATE_SERVICE_ID }

        if (-not $service) {
            Write-Log "Adding Microsoft Update Service..." -Severity 'Info'
            $serviceManager.AddService2($MICROSOFT_UPDATE_SERVICE_ID, 7, "")

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
        $errorCode = "0x{0:X8}" -f $_.Exception.HResult
        Get-WindowsUpdateErrorInfo -ErrorCode $errorCode
    }
    finally {
        if ($serviceManager) {
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($serviceManager) | Out-Null
        }
    }
    return $false
}

#endregion

#region Task Scheduling

function Create-UpdateTask {
    $taskName = "WindowsDriverUpdaterTask"

    try {
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Write-Log "Scheduled task already exists" -Severity 'Info'
            return $true
        }

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

#endregion

#region Reboot Management

function Test-PendingReboot {
    $rebootRequired = $false

    $updateKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending"
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

function Invoke-SafeReboot {
    Write-Log "Preparing for system reboot..." -Severity 'Info'

    $script:state.RebootCount++

    if ($script:state.RebootCount -ge $MAX_REBOOT_CYCLES) {
        Write-Log "Maximum reboot cycles ($MAX_REBOOT_CYCLES) reached. Stopping to prevent loop." -Severity 'Error'
        Clear-ScriptState
        Delete-UpdateTask
        return $false
    }

    Save-ScriptState

    if (-not (Create-UpdateTask)) {
        Write-Log "Failed to create scheduled task for post-reboot" -Severity 'Error'
        return $false
    }

    Write-Log "Rebooting system (Reboot $($script:state.RebootCount) of $MAX_REBOOT_CYCLES)..." -Severity 'Info'

    Remove-ScriptLock

    Restart-Computer -Force
    exit 0
}

#endregion

#region Windows Updates

function Install-AllWindowsUpdates {
    Write-Log "Checking for ALL Windows updates..." -Severity 'Info'

    if (-not (Ensure-PSWindowsUpdateModule)) {
        Write-Log "PSWindowsUpdate module not available, using COM fallback" -Severity 'Warning'
        return Install-AllWindowsUpdatesViaCOM
    }

    $retryCount = 0
    while ($retryCount -lt $MAX_RETRIES) {
        try {
            Write-Log "Searching for ALL Windows updates (Attempt $($retryCount + 1)/$MAX_RETRIES)..." -Severity 'Info'
            $updates = Get-WindowsUpdate -MicrosoftUpdate -IsHidden $false -AcceptAll -ErrorAction Stop

            if ($updates.Count -eq 0) {
                Write-Log "No Windows updates available" -Severity 'Info'
                return @{ Success = $true; RebootRequired = $false; UpdateCount = 0 }
            }

            Write-Log "Found $($updates.Count) Windows updates:" -Severity 'Info'
            foreach ($update in $updates) {
                $sizeInMB = if ($update.Size) { [math]::Round($update.Size / 1MB, 2) } else { "Unknown" }
                Write-Log "  - $($update.Title) (${sizeInMB}MB)" -Severity 'Info'
            }

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

                    if ($_.Exception.HResult) {
                        $errorCode = "0x{0:X8}" -f $_.Exception.HResult
                        Get-WindowsUpdateErrorInfo -ErrorCode $errorCode
                    }
                }

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
            $retryCount++
            $delaySeconds = [Math]::Min($RETRY_DELAY * [Math]::Pow(2, $retryCount - 1), 300)

            Write-Log "Error in PSWindowsUpdate method: $($_.Exception.Message)" -Severity 'Error'

            if ($_.Exception.HResult) {
                $errorCode = "0x{0:X8}" -f $_.Exception.HResult
                Get-WindowsUpdateErrorInfo -ErrorCode $errorCode
            }

            if ($retryCount -lt $MAX_RETRIES) {
                Write-Log "Retrying in $delaySeconds seconds (Attempt $($retryCount + 1)/$MAX_RETRIES)..." -Severity 'Warning'
                Start-Sleep -Seconds $delaySeconds
            }
            else {
                Write-Log "Max retries reached. Falling back to COM interface..." -Severity 'Warning'
                return Install-AllWindowsUpdatesViaCOM
            }
        }
    }
}

function Install-AllWindowsUpdatesViaCOM {
    Write-Log "Using COM interface for ALL Windows updates..." -Severity 'Info'

    $updateSession = $null
    $updateSearcher = $null
    $updatesToInstall = $null
    $installer = $null

    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()

        $updateSearcher.ServerSelection = 3
        $updateSearcher.ServiceID = $MICROSOFT_UPDATE_SERVICE_ID

        $searchCriteria = "IsInstalled=0 and IsHidden=0"
        Write-Log "Searching with criteria: $searchCriteria" -Severity 'Info'

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

        Write-Log "Downloading Windows updates..." -Severity 'Info'
        $downloader = $updateSession.CreateUpdateDownloader()
        $downloader.Updates = $updatesToInstall
        $downloadResult = $downloader.Download()

        if ($downloadResult.ResultCode -ne 2) {
            Write-Log "Download failed with code: $($downloadResult.ResultCode)" -Severity 'Error'
            $errorCode = "0x{0:X8}" -f $downloadResult.HResult
            Get-WindowsUpdateErrorInfo -ErrorCode $errorCode
            return @{ Success = $false; RebootRequired = $false; UpdateCount = 0 }
        }

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

        if ($_.Exception.HResult) {
            $errorCode = "0x{0:X8}" -f $_.Exception.HResult
            Get-WindowsUpdateErrorInfo -ErrorCode $errorCode
        }

        return @{ Success = $false; RebootRequired = $false; UpdateCount = 0 }
    }
    finally {
        if ($installer) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($installer) | Out-Null }
        if ($updatesToInstall) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($updatesToInstall) | Out-Null }
        if ($updateSearcher) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($updateSearcher) | Out-Null }
        if ($updateSession) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($updateSession) | Out-Null }
    }
}

#endregion

#region Additional Update Components

function Update-WinGetPackages {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Log "WinGet not available" -Severity 'Info'
        return
    }

    try {
        Write-Log "Checking WinGet packages..." -Severity 'Info'

        $updates = winget upgrade --accept-source-agreements 2>&1
        $updateList = $updates | Select-String -Pattern "^\S+\s+\S+\s+->\s+\S+" | ForEach-Object {
            $parts = $_.Line -split '\s+'
            $parts[0]
        }

        if ($updateList.Count -eq 0) {
            Write-Log "No WinGet updates available" -Severity 'Info'
            return
        }

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

function Update-StoreApps {
    Write-Log "Updating Microsoft Store applications..." -Severity 'Info'

    try {
        if (-not (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue)) {
            Write-Log "Store app management not available on this system" -Severity 'Warning'
            return
        }

        # Trigger Store update check using CIM
        try {
            $namespaceName = "Root\cimv2\mdm\dmmap"
            $className = "MDM_EnterpriseModernAppManagement_AppManagement01"
            Get-CimInstance -Namespace $namespaceName -ClassName $className -ErrorAction Stop |
                Invoke-CimMethod -MethodName UpdateScanMethod -ErrorAction Stop
            Write-Log "Microsoft Store update scan initiated" -Severity 'Success'
        }
        catch {
            # Fallback: Try using wsreset
            Write-Log "Fallback: Resetting Microsoft Store cache..." -Severity 'Info'
            Start-Process "wsreset.exe" -NoNewWindow -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5
            Write-Log "Store cache reset completed" -Severity 'Info'
        }
    }
    catch {
        Write-Log "Failed to update Store apps: $($_.Exception.Message)" -Severity 'Warning'
        Write-Log "Manual solution: Open Microsoft Store > Library > Get updates" -Severity 'Info'
    }
}

function Update-DefenderDefinitions {
    Write-Log "Updating Windows Defender definitions..." -Severity 'Info'

    try {
        # Check if Defender is available
        if (Get-Command Update-MpSignature -ErrorAction SilentlyContinue) {
            Update-MpSignature -UpdateSource MicrosoftUpdateServer -ErrorAction Stop
            Write-Log "Windows Defender definitions updated successfully" -Severity 'Success'

            # Get current signature version
            $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($mpStatus) {
                Write-Log "  Antivirus version: $($mpStatus.AntivirusSignatureVersion)" -Severity 'Info'
                Write-Log "  Last signature update: $($mpStatus.AntivirusSignatureLastUpdated)" -Severity 'Info'
            }
        }
        else {
            Write-Log "Windows Defender not available or not enabled" -Severity 'Info'
        }
    }
    catch {
        Write-Log "Failed to update Defender definitions: $($_.Exception.Message)" -Severity 'Warning'
        Write-Log "Reference: https://support.microsoft.com/windows/microsoft-defender-offline-help-protect-my-pc-9306d528-64bf-4668-5b80-ff533f183d6c" -Severity 'Info'
    }
}

function Update-PowerShellModules {
    Write-Log "Checking for PowerShell module updates..." -Severity 'Info'

    try {
        $installedModules = Get-InstalledModule -ErrorAction SilentlyContinue

        if (-not $installedModules) {
            Write-Log "No PowerShell modules installed from gallery" -Severity 'Info'
            return
        }

        $updatedCount = 0
        foreach ($module in $installedModules) {
            try {
                $latestVersion = Find-Module -Name $module.Name -ErrorAction SilentlyContinue

                if ($latestVersion -and ($latestVersion.Version -gt $module.Version)) {
                    Write-Log "Updating module: $($module.Name) from $($module.Version) to $($latestVersion.Version)" -Severity 'Info'
                    Update-Module -Name $module.Name -Force -ErrorAction Stop
                    $updatedCount++
                }
            }
            catch {
                Write-Log "Failed to update module $($module.Name): $($_.Exception.Message)" -Severity 'Warning'
            }
        }

        if ($updatedCount -eq 0) {
            Write-Log "All PowerShell modules are up to date" -Severity 'Info'
        }
        else {
            Write-Log "Updated $updatedCount PowerShell module(s)" -Severity 'Success'
        }
    }
    catch {
        Write-Log "PowerShell module update error: $($_.Exception.Message)" -Severity 'Warning'
    }
}

#endregion

#region Progress Tracking

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

#endregion

#region Main Execution

function Invoke-MainExecution {
    $steps = @()

    $steps += "System Health Check"
    $steps += "Check Prerequisites"
    $steps += "Internet Connectivity"

    if ($script:state.CurrentPhase -ne "PostReboot") {
        $steps += "Module Installation"
        $steps += "Service Registration"
    }

    $steps += "Windows Updates"

    if ($script:updateMode -eq "All") {
        $steps += "Windows Defender Updates"
        $steps += "Microsoft Store Apps"
        $steps += "WinGet Updates"
        $steps += "PowerShell Modules"
    }

    $totalSteps = $steps.Count
    $currentStep = 0

    try {
        # Step: System Health Check
        $currentStep++
        Show-Progress -Activity "Windows Update Process" -Status "Running system health diagnostics" `
            -CurrentStep $currentStep -TotalSteps $totalSteps

        $healthReport = Test-SystemHealth

        # Attempt repair if critical services are down
        if ($healthReport.WindowsUpdateService -eq "ERROR" -or $healthReport.BITSService -eq "ERROR") {
            Write-Log "Critical services are down. Attempting repair..." -Severity 'Warning'
            Repair-WindowsUpdateComponents
        }

        # Step: Prerequisites
        $currentStep++
        Show-Progress -Activity "Windows Update Process" -Status "Checking prerequisites" `
            -CurrentStep $currentStep -TotalSteps $totalSteps

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

        # Step: Windows updates
        $currentStep++
        Show-Progress -Activity "Windows Update Process" -Status "Installing ALL Windows updates" `
            -CurrentStep $currentStep -TotalSteps $totalSteps

        $updateResult = Install-AllWindowsUpdates

        if ($updateResult.RebootRequired) {
            Write-Log "Reboot required after Windows updates" -Severity 'Info'
            Invoke-SafeReboot
            return
        }

        # Step: Additional components (if configured)
        if ($script:updateMode -eq "All") {
            # Defender updates
            $currentStep++
            Show-Progress -Activity "Windows Update Process" -Status "Updating Windows Defender" `
                -CurrentStep $currentStep -TotalSteps $totalSteps
            Update-DefenderDefinitions

            # Store apps
            $currentStep++
            Show-Progress -Activity "Windows Update Process" -Status "Updating Microsoft Store apps" `
                -CurrentStep $currentStep -TotalSteps $totalSteps
            Update-StoreApps

            # WinGet packages
            $currentStep++
            Show-Progress -Activity "Windows Update Process" -Status "Updating applications via WinGet" `
                -CurrentStep $currentStep -TotalSteps $totalSteps
            Update-WinGetPackages

            # PowerShell modules
            $currentStep++
            Show-Progress -Activity "Windows Update Process" -Status "Updating PowerShell modules" `
                -CurrentStep $currentStep -TotalSteps $totalSteps
            Update-PowerShellModules
        }

        # Complete
        Write-Progress -Activity "Windows Update Process" -Completed
        Write-Log "=== Update Process Completed Successfully ===" -Severity 'Success'

        # Show summary
        Write-Log "`nUpdate Summary:" -Severity 'Info'
        Write-Log "  Successful Updates: $($script:state.SuccessfulUpdates.Count)" -Severity 'Info'
        Write-Log "  Failed Updates: $($script:state.FailedUpdates.Count)" -Severity 'Info'
        Write-Log "  Reboot Cycles: $($script:state.RebootCount)" -Severity 'Info'
        Write-Log "`nFor detailed information, see:" -Severity 'Info'
        Write-Log "  Log file: $logFile" -Severity 'Info'
        Write-Log "  Diagnostic report: $diagnosticLogFile" -Severity 'Info'
        Write-Log "`nMicrosoft Documentation:" -Severity 'Info'
        Write-Log "  Windows Update: $($script:MSDocLinks.WindowsUpdate)" -Severity 'Info'
        Write-Log "  Troubleshooting: $($script:MSDocLinks.TroubleshootUpdate)" -Severity 'Info'

        # Clean up
        Clear-ScriptState
        Delete-UpdateTask
    }
    catch {
        Write-Log "Critical error: $($_.Exception.Message)" -Severity 'Error'
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Severity 'Error'

        if ($_.Exception.HResult) {
            $errorCode = "0x{0:X8}" -f $_.Exception.HResult
            Get-WindowsUpdateErrorInfo -ErrorCode $errorCode
        }

        Write-Log "`nTroubleshooting Resources:" -Severity 'Info'
        Write-Log "  1. Check log file: $logFile" -Severity 'Info'
        Write-Log "  2. Check diagnostic report: $diagnosticLogFile" -Severity 'Info'
        Write-Log "  3. Microsoft Support: $($script:MSDocLinks.TroubleshootUpdate)" -Severity 'Info'
        Write-Log "  4. Consider running Windows Update Troubleshooter from Settings" -Severity 'Info'

        Save-ScriptState
    }
    finally {
        Write-Progress -Activity "Windows Update Process" -Completed
        Remove-ScriptLock
    }
}

#endregion

#region Audio Notification

function Invoke-DarudeSandstorm {
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
            [System.Media.SystemSounds]::Exclamation.Play()
            break
        }
    }
}

#endregion

#region Entry Point

# Check for admin privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Invoke-DarudeSandstorm
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
    Write-Log "=== Windows Comprehensive Updater - Enhanced Version ===" -Severity 'Info'
    Write-Log "Correlation ID: $($script:correlationId)" -Severity 'Info'
    Write-Log "Update Mode: $($script:updateMode)" -Severity 'Info'
    Write-Log "Interactive Mode: $($script:isInteractive)" -Severity 'Info'
    Write-Log "Script Version: 3.0 (Enhanced with Fail-Safe Mechanisms)" -Severity 'Info'

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
    Write-Log "`nPlease check the diagnostic report at: $diagnosticLogFile" -Severity 'Info'
}
finally {
    Remove-ScriptLock

    $executionTime = [math]::Round(((Get-Date) - $scriptStartTime).TotalMinutes, 2)
    Write-Log "Execution time: $executionTime minutes" -Severity 'Info'
    Write-Log "Log file: $logFile" -Severity 'Info'
    Write-Log "Diagnostic report: $diagnosticLogFile" -Severity 'Info'

    # Only prompt if interactive and not scheduled task
    if ($script:isInteractive -and -not $env:TASK_SCHEDULER) {
        Invoke-DarudeSandstorm
        Write-Host "`nPress any key to exit..." -ForegroundColor Cyan
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

#endregion
