# WindowsComprehensiveUpdateScript.ps1

# Set execution policy to bypass for this session
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force

# Define log file path
$scriptDir = $PSScriptRoot
$logFile = Join-Path -Path $scriptDir -ChildPath "WindowsUpdateLog.txt"

# Constants
$MICROSOFT_UPDATE_SERVICE_ID = "7971f918-a847-4430-9279-4a52d1efe18d"
$MAX_LOG_SIZE = 5MB
$MAX_RETRIES = 5
$RETRY_DELAY = 15
$TIMEOUT_MINUTES = 30

# Initialize debug tracking
$script:correlationId = [guid]::NewGuid().ToString()
$global:ErrorActionPreference = 'Stop'
$scriptStartTime = Get-Date

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

# Function to check internet connection with multiple servers
function Check-Internet {
    Write-Log "Checking for internet connection..." -Severity 'Info'
    $testServers = @(
        "update.microsoft.com",
        "windowsupdate.microsoft.com",
        "www.microsoft.com",
        "8.8.8.8"
    )

    $connected = $false
    foreach ($server in $testServers) {
        try {
            if (Test-NetConnection -ComputerName $server -InformationLevel Quiet -WarningAction SilentlyContinue) {
                Write-Log "Internet connection confirmed via $server" -Severity 'Info'
                $connected = $true
                break
            }
        } catch {
            Write-Log "Could not reach $server" -Severity 'Warning'
        }
    }

    if (-not $connected) {
        Write-Log "No internet connection detected. Please connect to the internet and run the script again." -Severity 'Error'
        throw "Internet connection required for Windows Update operations"
    }
}

# Function to install required modules with exponential backoff
function Install-RequiredModules {
    Write-Log "Checking and installing required modules..." -Severity 'Info'
    $retryCount = 0
    while ($retryCount -lt $MAX_RETRIES) {
        try {
            if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
                Write-Log "Installing NuGet package provider..." -Severity 'Info'
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop
                Write-Log "Setting PSGallery as trusted repository..." -Severity 'Info'
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
                Write-Log "Installing PSWindowsUpdate module..." -Severity 'Info'
                Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
                Write-Log "PSWindowsUpdate module installed successfully." -Severity 'Info'
            } else {
                Write-Log "PSWindowsUpdate module already available." -Severity 'Info'
            }
            # Verify module load capability
            Import-Module PSWindowsUpdate -Force -ErrorAction Stop
            $moduleVersion = (Get-Module PSWindowsUpdate).Version
            Write-Log "PSWindowsUpdate module loaded successfully (Version: $moduleVersion)" -Severity 'Info'
            return
        } catch {
            $retryCount++
            $delaySeconds = [Math]::Min($RETRY_DELAY * [Math]::Pow(2, $retryCount - 1), 300) # Exponential backoff, max 5 minutes
            Write-Log "Module installation attempt $retryCount failed: $($_.Exception.Message)" -Severity 'Warning'
            if ($retryCount -ge $MAX_RETRIES) {
                Write-Log "Failed to install PSWindowsUpdate module after $MAX_RETRIES attempts" -Severity 'Error'
                throw
            }
            Write-Log "Retrying in $delaySeconds seconds..." -Severity 'Info'
            Start-Sleep -Seconds $delaySeconds
        }
    }
}

# Function to register Microsoft Update Service with proper COM cleanup
function Register-MicrosoftUpdateService {
    Write-Log "Registering Microsoft Update Service..." -Severity 'Info'
    $serviceManager = $null
    try {
        $serviceManager = New-Object -ComObject Microsoft.Update.ServiceManager -ErrorAction Stop
        if (-not $serviceManager) {
            throw [UpdateException]::new("Failed to create ServiceManager COM object")
        }

        $service = $serviceManager.Services | Where-Object { $_.ServiceID -eq $MICROSOFT_UPDATE_SERVICE_ID }
        if (-not $service) {
            Write-Log "Microsoft Update Service not found. Registering..." -Severity 'Info'
            $serviceManager.AddService2($MICROSOFT_UPDATE_SERVICE_ID, 7, "")

            # Wait and verify service registration
            Start-Sleep -Seconds 2
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
    } finally {
        # Proper COM object cleanup
        if ($serviceManager) {
            try {
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($serviceManager) | Out-Null
                Write-Log "ServiceManager COM object released" -Severity 'Info'
            } catch {
                Write-Log "Warning: Could not release ServiceManager COM object: $($_.Exception.Message)" -Severity 'Warning'
            }
        }
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

# Function to test for pending reboot with corrected registry checks
function Test-PendingReboot {
    try {
        $rebootIndicators = @(
            @{
                TestType = "KeyExists"
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
                Description = "Component Based Servicing Reboot Pending"
            },
            @{
                TestType = "KeyExists"
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
                Description = "Windows Update Reboot Required"
            },
            @{
                TestType = "ValueExists"
                Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
                Name = "PendingFileRenameOperations"
                Description = "Pending File Rename Operations"
            }
        )

        foreach ($indicator in $rebootIndicators) {
            try {
                if ($indicator.TestType -eq "KeyExists") {
                    if (Test-Path $indicator.Path) {
                        Write-Log "Pending reboot detected: $($indicator.Description)" -Severity 'Warning'
                        return $true
                    }
                } elseif ($indicator.TestType -eq "ValueExists") {
                    $value = Get-ItemProperty -Path $indicator.Path -Name $indicator.Name -ErrorAction SilentlyContinue
                    if ($value -and $value.($indicator.Name)) {
                        Write-Log "Pending reboot detected: $($indicator.Description)" -Severity 'Warning'
                        return $true
                    }
                }
            } catch {
                Write-Log "Could not check reboot indicator: $($indicator.Description) - $($_.Exception.Message)" -Severity 'Warning'
            }
        }

        Write-Log "No pending reboot detected." -Severity 'Info'
        return $false
    } catch {
        Write-Log "Error checking pending reboot: $($_.Exception.Message)" -Severity 'Warning'
        return $false
    }
}

# Function to install all Windows updates and handle reboots
function Install-Updates {
    Write-Log "Checking for available Windows updates (all categories)..." -Severity 'Info'
    try {
        # Get ALL available updates including optional updates (drivers, firmware, etc.)
        Write-Log "Searching for all Windows updates including optional updates using PSWindowsUpdate module..." -Severity 'Info'
        $updates = Get-WindowsUpdate -MicrosoftUpdate -IsHidden $false -ErrorAction Stop

        if ($updates.Count -gt 0) {
            Write-Log "Found $($updates.Count) Windows updates:" -Severity 'Info'

            # Categorize updates for better logging (including optional updates)
            $securityUpdates = $updates | Where-Object { $_.Categories -match "Security Updates" }
            $criticalUpdates = $updates | Where-Object { $_.Categories -match "Critical Updates" }
            $driverUpdates = $updates | Where-Object { $_.Categories -match "Drivers" }
            $featureUpdates = $updates | Where-Object { $_.Categories -match "Feature Packs|Upgrades" }
            $qualityUpdates = $updates | Where-Object { $_.Categories -match "Update Rollups|Updates" }
            $optionalUpdates = $updates | Where-Object { $_.Categories -match "Optional|Hardware" -or $_.IsOptional -eq $true }

            Write-Log "Update breakdown: Security($($securityUpdates.Count)), Critical($($criticalUpdates.Count)), Drivers($($driverUpdates.Count)), Features($($featureUpdates.Count)), Quality($($qualityUpdates.Count)), Optional($($optionalUpdates.Count))" -Severity 'Info'

            foreach ($update in $updates) {
                $sizeInMB = if ($update.Size) { [math]::Round($update.Size / 1MB, 2) } else { "Unknown" }
                $category = ($update.Categories -split ",")[0]
                $optionalFlag = if ($update.IsOptional) { " [OPTIONAL]" } else { "" }
                Write-Log "  - [$category] $($update.Title) (Size: ${sizeInMB}MB)$optionalFlag" -Severity 'Info'
            }

            Write-Log "Installing ALL $($updates.Count) Windows updates (including optional updates)..." -Severity 'Info'
            $installResult = Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IsHidden $false -IgnoreReboot -ErrorAction Stop -Verbose:$false

            # Log installation results
            if ($installResult) {
                foreach ($result in $installResult) {
                    $status = if ($result.Result -eq "Installed") { "Success" } else { "Failed" }
                    Write-Log "Update result: $($result.Title) - $status" -Severity 'Info'
                }
            }

            if (Test-PendingReboot) {
                Write-Log "Reboot required after Windows updates. Creating scheduled task and rebooting..." -Severity 'Info'
                Create-UpdateTask
                Start-Sleep -Seconds 5  # Brief delay before reboot
                Restart-Computer -Force
            } else {
                Write-Log "All Windows updates installed successfully. No reboot required." -Severity 'Info'
            }
        } else {
            Write-Log "No Windows updates available via PSWindowsUpdate. Trying fallback method..." -Severity 'Info'
            Install-UpdatesViaCOM
        }
    } catch {
        Write-Log "Error installing updates with PSWindowsUpdate: $($_.Exception.Message)" -Severity 'Warning'
        Write-Log "Falling back to COM interface..." -Severity 'Info'
        Install-UpdatesViaCOM
    } finally {
        # Clean up if no reboot is pending
        if (-not (Test-PendingReboot)) {
            Write-Log "All Windows updates processed. Cleaning up and opening log..." -Severity 'Info'
            Delete-UpdateTask
            Open-LogFile
        }
    }
}

# Fallback function to install updates via COM with proper cleanup
function Install-UpdatesViaCOM {
    $updateSession = $null
    $updateSearcher = $null
    $updatesToInstall = $null
    $installer = $null

    try {
        Write-Log "Initializing Windows Update COM objects..." -Severity 'Info'
        $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $updateSearcher = $updateSession.CreateUpdateSearcher()

        # Search for ALL available updates including optional (hidden=false)
        $searchCriteria = "IsInstalled=0 and IsHidden=0"
        Write-Log "Searching for all Windows updates including optional using criteria: $searchCriteria" -Severity 'Info'
        $searchResult = $updateSearcher.Search($searchCriteria)

        if ($searchResult.Updates.Count -gt 0) {
            Write-Log "Found $($searchResult.Updates.Count) Windows updates via COM. Processing..." -Severity 'Info'

            # Log update details including optional status
            foreach ($update in $searchResult.Updates) {
                $sizeInMB = [math]::Round($update.MaxDownloadSize / 1MB, 2)
                $optionalFlag = if ($update.IsOptional) { " [OPTIONAL]" } else { "" }
                Write-Log "  - $($update.Title) (Size: ${sizeInMB}MB)$optionalFlag" -Severity 'Info'
            }

            $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl -ErrorAction Stop
            foreach ($update in $searchResult.Updates) {
                if ($update.IsInstalled -eq $false) {
                    $updatesToInstall.Add($update)
                }
            }

            if ($updatesToInstall.Count -gt 0) {
                $installer = $updateSession.CreateUpdateInstaller()
                $installer.Updates = $updatesToInstall
                Write-Log "Installing $($updatesToInstall.Count) driver updates..." -Severity 'Info'
                $installResult = $installer.Install()

                # Interpret result codes
                $resultMessage = switch ($installResult.ResultCode) {
                    0 { "Not Started" }
                    1 { "In Progress" }
                    2 { "Succeeded" }
                    3 { "Succeeded with Errors" }
                    4 { "Failed" }
                    5 { "Aborted" }
                    default { "Unknown ($($installResult.ResultCode))" }
                }

                Write-Log "COM update installation completed. Result: $resultMessage" -Severity 'Info'

                if ($installResult.ResultCode -eq 2 -or $installResult.ResultCode -eq 3) {
                    if (Test-PendingReboot) {
                        Write-Log "Reboot required. Creating scheduled task and rebooting..." -Severity 'Info'
                        Create-UpdateTask
                        Restart-Computer -Force
                    }
                } else {
                    Write-Log "Update installation failed or was incomplete" -Severity 'Warning'
                }
            } else {
                Write-Log "No updates available for installation" -Severity 'Info'
            }
        } else {
            Write-Log "No Windows updates available via COM." -Severity 'Info'
            if (-not (Test-PendingReboot)) {
                Write-Log "All updates installed and no reboot pending. Cleaning up and opening log..." -Severity 'Info'
                Delete-UpdateTask
                Open-LogFile
            }
        }
    } catch {
        Write-Log "Failed to install updates via COM: $($_.Exception.Message)" -Severity 'Error'
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Severity 'Error'
    } finally {
        # Proper COM object cleanup to prevent memory leaks
        if ($installer) {
            try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($installer) | Out-Null } catch { }
        }
        if ($updatesToInstall) {
            try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($updatesToInstall) | Out-Null } catch { }
        }
        if ($updateSearcher) {
            try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($updateSearcher) | Out-Null } catch { }
        }
        if ($updateSession) {
            try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($updateSession) | Out-Null } catch { }
        }
        Write-Log "COM objects cleanup completed" -Severity 'Info'
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

# Function to show progress with timeout
function Show-Progress {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete = 0
    )
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
    Write-Log "Progress: $Activity - $Status ($PercentComplete%)" -Severity 'Info'
}

# Function to run operations with timeout
function Invoke-WithTimeout {
    param(
        [scriptblock]$ScriptBlock,
        [int]$TimeoutMinutes = $TIMEOUT_MINUTES,
        [string]$OperationName = "Operation"
    )

    Write-Log "Starting $OperationName with $TimeoutMinutes minute timeout" -Severity 'Info'
    $job = Start-Job -ScriptBlock $ScriptBlock

    try {
        if (Wait-Job -Job $job -Timeout ($TimeoutMinutes * 60)) {
            $result = Receive-Job -Job $job
            Write-Log "$OperationName completed successfully" -Severity 'Info'
            return $result
        } else {
            Write-Log "$OperationName timed out after $TimeoutMinutes minutes" -Severity 'Warning'
            Stop-Job -Job $job
            throw "Operation timeout: $OperationName"
        }
    } finally {
        Remove-Job -Job $job -Force
    }
}

# Function to update WinGet packages
function Update-WinGetPackages {
    try {
        Write-Log "Checking for WinGet package updates..." -Severity 'Info'
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-Log "WinGet found. Checking for available package updates..." -Severity 'Info'

            # Get list of upgradable packages
            $wingetOutput = winget upgrade --source winget --disable-interactivity 2>&1
            $wingetString = $wingetOutput | Out-String

            if ($wingetString -match "No available upgrades") {
                Write-Log "No WinGet package updates available." -Severity 'Info'
            } else {
                Write-Log "WinGet package updates available. Installing..." -Severity 'Info'
                $upgradeResult = winget upgrade --all --silent --accept-source-agreements --accept-package-agreements --disable-interactivity 2>&1
                $upgradeString = $upgradeResult | Out-String

                if ($upgradeString -match "Successfully installed") {
                    Write-Log "WinGet packages updated successfully." -Severity 'Info'
                } else {
                    Write-Log "WinGet upgrade completed with mixed results. Check individual package status." -Severity 'Warning'
                }
            }
        } else {
            Write-Log "WinGet not available on this system. Skipping package updates." -Severity 'Warning'
        }
    } catch {
        Write-Log "Error updating WinGet packages: $($_.Exception.Message)" -Severity 'Warning'
    }
}

# Function to update Microsoft Store apps
function Update-StoreApps {
    try {
        Write-Log "Checking for Microsoft Store app updates..." -Severity 'Info'
        if (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue) {
            Write-Log "Triggering Microsoft Store app update scan..." -Severity 'Info'

            # Try to trigger Store app updates using CIM method
            try {
                $namespace = "Root\cimv2\mdm\dmmap"
                $className = "MDM_EnterpriseModernAppManagement_AppManagement01"
                $cimInstance = Get-CimInstance -Namespace $namespace -ClassName $className -ErrorAction SilentlyContinue

                if ($cimInstance) {
                    Invoke-CimMethod -CimInstance $cimInstance -MethodName UpdateScanMethod
                    Write-Log "Store app update scan initiated via CIM." -Severity 'Info'
                } else {
                    Write-Log "CIM method not available. Trying PowerShell alternative..." -Severity 'Info'

                    # Alternative method using PowerShell jobs
                    $storeUpdateJob = Start-Job -ScriptBlock {
                        try {
                            # Try to force Store updates using ms-windows-store protocol
                            Start-Process "ms-windows-store://downloadsandupdates" -ErrorAction SilentlyContinue
                            Start-Sleep -Seconds 10

                            # Get list of all user apps and check for updates
                            $packages = Get-AppxPackage -AllUsers | Where-Object { $_.SignatureKind -eq 'Store' }
                            return "Found $($packages.Count) Store packages"
                        } catch {
                            return "Error: $($_.Exception.Message)"
                        }
                    }

                    $storeResult = Wait-Job -Job $storeUpdateJob -Timeout 30 | Receive-Job
                    Remove-Job -Job $storeUpdateJob -Force
                    Write-Log "Store update attempt: $storeResult" -Severity 'Info'
                }
            } catch {
                Write-Log "Could not trigger Store app updates: $($_.Exception.Message)" -Severity 'Warning'
            }
        } else {
            Write-Log "AppX packages not available on this system." -Severity 'Warning'
        }
    } catch {
        Write-Log "Error updating Store apps: $($_.Exception.Message)" -Severity 'Warning'
    }
}

# Function to update Windows Defender definitions
function Update-DefenderDefinitions {
    try {
        Write-Log "Updating Windows Defender definitions..." -Severity 'Info'

        # Check if Windows Defender is available
        if (Get-Command Update-MpSignature -ErrorAction SilentlyContinue) {
            Write-Log "Updating Windows Defender signature definitions..." -Severity 'Info'
            Update-MpSignature -UpdateSource WindowsUpdate
            Write-Log "Windows Defender definitions updated successfully." -Severity 'Info'

            # Get current signature version
            try {
                $mpPreference = Get-MpPreference -ErrorAction SilentlyContinue
                if ($mpPreference) {
                    $signatureInfo = Get-MpComputerStatus -ErrorAction SilentlyContinue
                    if ($signatureInfo) {
                        Write-Log "Current Defender signature version: $($signatureInfo.AntivirusSignatureVersion)" -Severity 'Info'
                        Write-Log "Last signature update: $($signatureInfo.AntivirusSignatureLastUpdated)" -Severity 'Info'
                    }
                }
            } catch {
                Write-Log "Could not retrieve Defender signature information: $($_.Exception.Message)" -Severity 'Warning'
            }
        } else {
            Write-Log "Windows Defender PowerShell module not available. Trying alternative method..." -Severity 'Warning'

            # Alternative method using MpCmdRun.exe
            $mpCmdPath = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
            if (Test-Path $mpCmdPath) {
                Write-Log "Updating Defender definitions using MpCmdRun.exe..." -Severity 'Info'
                $mpResult = Start-Process -FilePath $mpCmdPath -ArgumentList "-SignatureUpdate" -Wait -PassThru -NoNewWindow
                if ($mpResult.ExitCode -eq 0) {
                    Write-Log "Defender definitions updated successfully via MpCmdRun." -Severity 'Info'
                } else {
                    Write-Log "MpCmdRun returned exit code: $($mpResult.ExitCode)" -Severity 'Warning'
                }
            } else {
                Write-Log "Windows Defender not found on this system." -Severity 'Warning'
            }
        }
    } catch {
        Write-Log "Error updating Defender definitions: $($_.Exception.Message)" -Severity 'Warning'
    }
}

# Function to update PowerShell modules
function Update-PowerShellModules {
    try {
        Write-Log "Checking for PowerShell module updates..." -Severity 'Info'

        # Get all installed modules
        $installedModules = Get-InstalledModule -ErrorAction SilentlyContinue

        if ($installedModules) {
            Write-Log "Found $($installedModules.Count) installed PowerShell modules. Checking for updates..." -Severity 'Info'

            $outdatedModules = @()
            foreach ($module in $installedModules) {
                try {
                    $latestVersion = Find-Module -Name $module.Name -ErrorAction SilentlyContinue
                    if ($latestVersion -and ($latestVersion.Version -gt $module.Version)) {
                        $outdatedModules += $module
                        Write-Log "Module update available: $($module.Name) $($module.Version) -> $($latestVersion.Version)" -Severity 'Info'
                    }
                } catch {
                    Write-Log "Could not check updates for module: $($module.Name)" -Severity 'Warning'
                }
            }

            if ($outdatedModules.Count -gt 0) {
                Write-Log "Updating $($outdatedModules.Count) PowerShell modules..." -Severity 'Info'
                foreach ($module in $outdatedModules) {
                    try {
                        Write-Log "Updating module: $($module.Name)" -Severity 'Info'
                        Update-Module -Name $module.Name -Force -AcceptLicense -ErrorAction Stop
                        Write-Log "Successfully updated module: $($module.Name)" -Severity 'Info'
                    } catch {
                        Write-Log "Failed to update module $($module.Name): $($_.Exception.Message)" -Severity 'Warning'
                    }
                }
            } else {
                Write-Log "All PowerShell modules are up to date." -Severity 'Info'
            }
        } else {
            Write-Log "No installed PowerShell modules found to update." -Severity 'Info'
        }
    } catch {
        Write-Log "Error updating PowerShell modules: $($_.Exception.Message)" -Severity 'Warning'
    }
}

# Function to perform system integrity checks
function Invoke-SystemIntegrityCheck {
    try {
        Write-Log "Running system file integrity checks..." -Severity 'Info'

        # Run SFC scan
        Write-Log "Starting System File Checker (SFC) scan..." -Severity 'Info'
        $sfcProcess = Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\sfc_output.txt"

        if (Test-Path "$env:TEMP\sfc_output.txt") {
            $sfcOutput = Get-Content "$env:TEMP\sfc_output.txt" -ErrorAction SilentlyContinue
            if ($sfcOutput) {
                $sfcResult = $sfcOutput | Select-String "Windows Resource Protection" | Select-Object -Last 1
                if ($sfcResult) {
                    Write-Log "SFC Result: $($sfcResult.Line)" -Severity 'Info'
                }
            }
            Remove-Item "$env:TEMP\sfc_output.txt" -Force -ErrorAction SilentlyContinue
        }

        if ($sfcProcess.ExitCode -eq 0) {
            Write-Log "System File Checker completed successfully." -Severity 'Info'
        } else {
            Write-Log "System File Checker returned exit code: $($sfcProcess.ExitCode)" -Severity 'Warning'
        }

        # Run DISM health check
        Write-Log "Starting DISM component store health check..." -Severity 'Info'
        try {
            $dismProcess = Start-Process -FilePath "DISM.exe" -ArgumentList "/Online", "/Cleanup-Image", "/RestoreHealth" -Wait -PassThru -NoNewWindow
            if ($dismProcess.ExitCode -eq 0) {
                Write-Log "DISM health restoration completed successfully." -Severity 'Info'
            } else {
                Write-Log "DISM returned exit code: $($dismProcess.ExitCode)" -Severity 'Warning'
            }
        } catch {
            Write-Log "Error running DISM: $($_.Exception.Message)" -Severity 'Warning'
        }

        Write-Log "System integrity checks completed." -Severity 'Info'
    } catch {
        Write-Log "Error during system integrity check: $($_.Exception.Message)" -Severity 'Warning'
    }
}

# Main execution block with progress tracking
try {
    $totalSteps = 11  # Updated to include all new components
    $currentStep = 0

    # Step 1: Check admin privileges
    $currentStep++
    Show-Progress -Activity "Windows Comprehensive Updater" -Status "Checking administrative privileges" -PercentComplete ([math]::Round(($currentStep / $totalSteps) * 100))

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "Script not running with administrative privileges. Attempting to elevate..." -Severity 'Warning'
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    }
    Write-Log "Administrative privileges confirmed." -Severity 'Info'

    # Step 2: Initialize
    $currentStep++
    Show-Progress -Activity "Windows Comprehensive Updater" -Status "Initializing script" -PercentComplete ([math]::Round(($currentStep / $totalSteps) * 100))
    Write-Log "=== Windows Comprehensive Update Script Started ===" -Severity 'Info'
    Write-Log "Correlation ID: $script:correlationId" -Severity 'Info'
    Write-Log "Script Path: $PSCommandPath" -Severity 'Info'
    Write-Log "Log File: $logFile" -Severity 'Info'

    # Detect Windows version for full OS updates
    $osVersion = Get-CimInstance -ClassName Win32_OperatingSystem
    $windowsVersion = $osVersion.Caption
    $buildNumber = $osVersion.BuildNumber
    Write-Log "Detected OS: $windowsVersion (Build: $buildNumber)" -Severity 'Info'

    if ($buildNumber -ge 22000) {
        Write-Log "Windows 11 detected - will ensure full Windows 11 updates including feature updates" -Severity 'Info'
    } elseif ($buildNumber -ge 10240) {
        Write-Log "Windows 10 detected - will ensure full Windows 10 updates including feature updates" -Severity 'Info'
    } else {
        Write-Log "Older Windows version detected - will install available updates" -Severity 'Info'
    }

    # Step 3: Check internet connection
    $currentStep++
    Show-Progress -Activity "Windows Comprehensive Updater" -Status "Checking internet connectivity" -PercentComplete ([math]::Round(($currentStep / $totalSteps) * 100))
    Check-Internet

    # Step 4: Install required modules
    $currentStep++
    Show-Progress -Activity "Windows Comprehensive Updater" -Status "Installing required PowerShell modules" -PercentComplete ([math]::Round(($currentStep / $totalSteps) * 100))
    Install-RequiredModules

    # Step 5: Register Microsoft Update Service
    $currentStep++
    Show-Progress -Activity "Windows Comprehensive Updater" -Status "Registering Microsoft Update Service" -PercentComplete ([math]::Round(($currentStep / $totalSteps) * 100))
    Register-MicrosoftUpdateService

    # Step 6: Install Windows updates
    $currentStep++
    Show-Progress -Activity "Windows Comprehensive Updater" -Status "Searching and installing all Windows updates" -PercentComplete ([math]::Round(($currentStep / $totalSteps) * 100))
    Install-Updates

    # Step 7: Update WinGet packages
    $currentStep++
    Show-Progress -Activity "Windows Comprehensive Updater" -Status "Updating WinGet packages" -PercentComplete ([math]::Round(($currentStep / $totalSteps) * 100))
    Update-WinGetPackages

    # Step 8: Update Microsoft Store apps
    $currentStep++
    Show-Progress -Activity "Windows Comprehensive Updater" -Status "Updating Microsoft Store applications" -PercentComplete ([math]::Round(($currentStep / $totalSteps) * 100))
    Update-StoreApps

    # Step 9: Update Windows Defender definitions
    $currentStep++
    Show-Progress -Activity "Windows Comprehensive Updater" -Status "Updating Windows Defender definitions" -PercentComplete ([math]::Round(($currentStep / $totalSteps) * 100))
    Update-DefenderDefinitions

    # Step 10: Update PowerShell modules
    $currentStep++
    Show-Progress -Activity "Windows Comprehensive Updater" -Status "Updating PowerShell modules" -PercentComplete ([math]::Round(($currentStep / $totalSteps) * 100))
    Update-PowerShellModules

    # Step 11: System integrity checks
    $currentStep++
    Show-Progress -Activity "Windows Comprehensive Updater" -Status "Running system integrity checks" -PercentComplete ([math]::Round(($currentStep / $totalSteps) * 100))
    Invoke-SystemIntegrityCheck

    # Complete
    Write-Progress -Activity "Windows Comprehensive Updater" -Status "Completed" -PercentComplete 100
    Write-Log "=== Windows Comprehensive Update Script Completed Successfully ===" -Severity 'Info'
    Write-Log "Summary: All update categories processed - Windows Updates, WinGet packages, Store apps, Defender definitions, PowerShell modules, and system integrity checks." -Severity 'Info'

} catch {
    Write-Log "=== CRITICAL ERROR ===" -Severity 'Error'
    Write-Log "Error: $($_.Exception.Message)" -Severity 'Error'
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Severity 'Error'
    Write-Log "Correlation ID: $script:correlationId" -Severity 'Error'

    # Try to open log file on error
    try {
        Open-LogFile
    } catch {
        Write-Host "Could not open log file: $($_.Exception.Message)" -ForegroundColor Red
    }
} finally {
    Write-Progress -Activity "Windows Comprehensive Updater" -Completed
    Write-Host "`n=== Script Execution Summary ===" -ForegroundColor Cyan
    Write-Host "Log File: $logFile" -ForegroundColor White
    Write-Host "Correlation ID: $script:correlationId" -ForegroundColor White
    Write-Host "Execution Time: $([math]::Round(((Get-Date) - $scriptStartTime).TotalMinutes, 2)) minutes" -ForegroundColor White
    Write-Host "`nPress any key to exit..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
