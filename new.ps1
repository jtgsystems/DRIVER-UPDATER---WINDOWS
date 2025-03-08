# WindowsAutoUpdateScript.ps1

# Set execution policy to bypass for this session
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force

# Define log file path
$scriptDir = $PSScriptRoot
$logFile = Join-Path -Path $scriptDir -ChildPath "WindowsUpdateLog.txt"

# Constants
$MICROSOFT_UPDATE_SERVICE_ID = "7971f918-a847-4430-9279-4a52d1efe18d"
$MAX_LOG_SIZE = 5MB
$MAX_RETRIES = 3
$RETRY_DELAY = 30

# Initialize debug tracking
$script:correlationId = [guid]::NewGuid().ToString()
$global:ErrorActionPreference = 'Stop'

class UpdateException : Exception { }

# Function to write to log file and console
function Write-Log {
    param (
        [string]$Message,
        [string]$Severity = 'Info'
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Severity] $Message"
    Write-Host $logEntry
    
    try {
        # Rotate log if over size limit
        if (Test-Path $logFile -PathType Leaf) {
            $logSize = (Get-Item $logFile).Length
            if ($logSize -gt $MAX_LOG_SIZE) {
                $archivePath = Join-Path $scriptDir "WindowsUpdateLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
                Move-Item $logFile $archivePath -Force
            }
        }

        # Use stream writer for better performance
        $stream = [System.IO.StreamWriter]::new($logFile, $true)
        $stream.WriteLine("[$correlationId] $logEntry")
        $stream.Close()
    }
    catch {
        Write-Host "Fatal logging error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to check internet connection with flashing prompt
function Check-Internet {
    Write-Log "Checking for internet connection..." -Severity 'Info'
    while (-not (Test-NetConnection -ComputerName "www.google.com" -InformationLevel Quiet)) {
        Write-Host "`r[Connect to internet] " -ForegroundColor Yellow -BackgroundColor Red -NoNewline
        Start-Sleep -Seconds 1
        Write-Host "`r                        " -NoNewline
        Start-Sleep -Seconds 1
    }
    Write-Host "`rInternet connection established." -ForegroundColor Green
    Write-Log "Internet connection confirmed." -Severity 'Info'
}

# Function to install required modules
function Install-RequiredModules {
    Write-Log "Checking and installing required modules..." -Severity 'Info'
    $retryCount = 0
    while ($retryCount -lt $MAX_RETRIES) {
        try {
            if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
                Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -ErrorAction Stop
                Write-Log "PSWindowsUpdate module installed successfully." -Severity 'Info'
            }
            # Verify module load capability
            Import-Module PSWindowsUpdate -Force -ErrorAction Stop
            return
        } catch {
            $retryCount++
            Write-Log "Module installation attempt $retryCount failed: $($_.Exception.Message)" -Severity 'Warning'
            if ($retryCount -ge $MAX_RETRIES) { throw }
            Start-Sleep -Seconds $RETRY_DELAY
        }
    }

}

# Function to register Microsoft Update Service
function Register-MicrosoftUpdateService {
    Write-Log "Registering Microsoft Update Service..." -Severity 'Info'
    try {
        $serviceManager = New-Object -ComObject Microsoft.Update.ServiceManager -ErrorAction Stop
        $service = $serviceManager.Services | Where-Object { $_.ServiceID -eq $MICROSOFT_UPDATE_SERVICE_ID }
        if (-not $service) {
            $serviceManager.AddService2($MICROSOFT_UPDATE_SERVICE_ID, 7, "")
            # Verify service registration
            $newService = $serviceManager.Services | Where-Object { $_.ServiceID -eq $MICROSOFT_UPDATE_SERVICE_ID }
            if (-not $newService) {
                throw [UpdateException]::new("Service registration verification failed")
            }
            Write-Log "Microsoft Update Service registered successfully. DisplayName: $($newService.Name)" -Severity 'Info'
        } else {
            Write-Log "Microsoft Update Service already registered. DisplayName: $($service.Name)" -Severity 'Info'
        }
    } catch {
        Write-Log "Failed to register Microsoft Update Service: $($_.Exception.Message)" -Severity 'Error'
        throw
    }
}

# Function to create scheduled task for post-reboot execution
function Create-UpdateTask {
    $taskName = "WindowsAutoUpdateScriptTask"
    $taskPath = "\Microsoft\Windows\WindowsUpdate\"
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if (-not $task) {
        try {
            $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
            $trigger = New-ScheduledTaskTrigger -AtStartup
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
            
            # Validate task parameters
            if (-not $action -or -not $trigger -or -not $principal) {
                throw [UpdateException]::new("Scheduled task component creation failed")
            }
            
            $task = Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action `
                -Trigger $trigger -Principal $principal -Settings $settings `
                -Description "Runs WindowsAutoUpdateScript at startup" -Force -ErrorAction Stop
            
            Write-Log "Scheduled task created successfully. State: $($task.State)" -Severity 'Info'
        } catch {
            Write-Log "Failed to create scheduled task: $($_.Exception.Message)" -Severity 'Error'
            throw
        }
    }
}

# Function to delete scheduled task
function Delete-UpdateTask {
    $taskName = "WindowsAutoUpdateScriptTask"
    $taskPath = "\Microsoft\Windows\WindowsUpdate\"
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) {
        try {
            Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction Stop
            Write-Log "Scheduled task deleted successfully." -Severity 'Info'
        } catch {
            Write-Log "Failed to delete scheduled task: $($_.Exception.Message)" -Severity 'Warning'
        }
    }
}

# Function to test for pending reboot
function Test-PendingReboot {
    try {
        $rebootPending = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "RebootRequired" -ErrorAction SilentlyContinue) -or
                         (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue)
        if ($rebootPending) {
            Write-Log "Pending reboot detected." -Severity 'Info'
            return $true
        }
        Write-Log "No pending reboot detected." -Severity 'Info'
        return $false
    } catch {
        Write-Log "Error checking pending reboot: $($_.Exception.Message)" -Severity 'Warning'
        return $false
    }
}

# Function to install updates and handle reboots
function Install-Updates {
    Write-Log "Checking for available updates..." -Severity 'Info'
    try {
        $updates = Get-WindowsUpdate -MicrosoftUpdate -IsInstalled:$false -ErrorAction Stop
        if ($updates.Count -gt 0) {
            Write-Log "Found $($updates.Count) updates. Installing..." -Severity 'Info'
            Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
            if (Test-PendingReboot) {
                Write-Log "Reboot required. Creating scheduled task and rebooting..." -Severity 'Info'
                Create-UpdateTask
                Restart-Computer -Force
            }
        } else {
            Write-Log "No updates available." -Severity 'Info'
            if (-not (Test-PendingReboot)) {
                Write-Log "All updates installed and no reboot pending. Cleaning up and opening log..." -Severity 'Info'
                Delete-UpdateTask
                Open-LogFile
            }
        }
    } catch {
        Write-Log "Error installing updates with PSWindowsUpdate: $($_.Exception.Message). Falling back to COM." -Severity 'Warning'
        Install-UpdatesViaCOM
    }
}

# Fallback function to install updates via COM
function Install-UpdatesViaCOM {
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=0")
        if ($searchResult.Updates.Count -gt 0) {
            Write-Log "Found $($searchResult.Updates.Count) updates via COM. Installing..." -Severity 'Info'
            $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl -ErrorAction Stop
            foreach ($update in $searchResult.Updates) {
                if ($update.IsInstalled -eq $false) {
                    $updatesToInstall.Add($update)
                }
            }
            $installer = $updateSession.CreateUpdateInstaller()
            $installer.Updates = $updatesToInstall
            $installResult = $installer.Install()
            Write-Log "COM updates installed. Result: $($installResult.ResultCode)" -Severity 'Info'
            if (Test-PendingReboot) {
                Write-Log "Reboot required. Creating scheduled task and rebooting..." -Severity 'Info'
                Create-UpdateTask
                Restart-Computer -Force
            }
        } else {
            Write-Log "No updates available via COM." -Severity 'Info'
            if (-not (Test-PendingReboot)) {
                Write-Log "All updates installed and no reboot pending. Cleaning up and opening log..." -Severity 'Info'
                Delete-UpdateTask
                Open-LogFile
            }
        }
    } catch {
        Write-Log "Failed to install updates via COM: $($_.Exception.Message)" -Severity 'Error'
    }
}

# Function to open the log file
function Open-LogFile {
    Write-Log "Opening log file: $logFile" -Severity 'Info'
    try {
        Invoke-Item -Path $logFile
    } catch {
        Write-Log "Failed to open log file: $($_.Exception.Message)" -Severity 'Error'
    }
}

# Main execution block
try {
    # Check admin privileges and elevate if needed
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "Script not running with administrative privileges. Attempting to elevate..." -Severity 'Warning'
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    }

    Write-Log "Windows Update Script Started." -Severity 'Info'

    # Check internet connection
    Check-Internet

    # Install required modules
    Install-RequiredModules

    # Register Microsoft Update Service for driver updates
    Register-MicrosoftUpdateService

    # Install updates and handle reboots
    Install-Updates

} catch {
    Write-Log "Unexpected error: $($_.Exception.Message)" -Severity 'Error'
} finally {
    Write-Host "Press any key to exit..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}