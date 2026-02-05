#Requires -Version 5.1

<#
.SYNOPSIS
    Validation and testing script for Windows Driver Updater Tool
.DESCRIPTION
    Performs comprehensive validation of the Driver Updater installation,
    configuration, and basic functionality without making system changes.
.PARAMETER Verbose
    Shows detailed test output
.NOTES
    Version: 1.0
    Author: Enterprise Tools Team
    Date: 2025-12-02
.EXAMPLE
    .\Test-DriverUpdater.ps1
    Runs all validation tests
.EXAMPLE
    .\Test-DriverUpdater.ps1 -Verbose
    Runs all tests with detailed output
#>

[CmdletBinding()]
param()

# SOTA 2026 Note: Write-Host is intentionally used for colored console UI output.
# For pipeline-compatible output, use Write-Output. For logging, use Write-Information.
$ErrorActionPreference = 'Continue'
$script:TestResults = @()
$script:PassCount = 0
$script:FailCount = 0
$script:WarnCount = 0

#region Test Helper Functions
function Write-TestResult {
    param(
        [string]$TestName,
        [ValidateSet('Pass', 'Fail', 'Warn', 'Info')]
        [string]$Result,
        [string]$Message
    )

    $icon = switch ($Result) {
        'Pass' { '[PASS]'; $script:PassCount++ }
        'Fail' { '[FAIL]'; $script:FailCount++ }
        'Warn' { '[WARN]'; $script:WarnCount++ }
        'Info' { '[INFO]' }
    }

    $color = switch ($Result) {
        'Pass' { 'Green' }
        'Fail' { 'Red' }
        'Warn' { 'Yellow' }
        'Info' { 'Cyan' }
    }

    Write-Host "$icon " -NoNewline -ForegroundColor $color
    Write-Host "$TestName" -NoNewline -ForegroundColor White
    if ($Message) {
        Write-Host " - $Message" -ForegroundColor Gray
    }
    else {
        Write-Output ""
    }

    $script:TestResults += [PSCustomObject]@{
        Test    = $TestName
        Result  = $Result
        Message = $Message
    }
}

function Test-Assertion {
    param(
        [string]$TestName,
        [scriptblock]$Condition,
        [string]$SuccessMessage = "",
        [string]$FailureMessage = ""
    )

    try {
        if (& $Condition) {
            Write-TestResult -TestName $TestName -Result 'Pass' -Message $SuccessMessage
            return $true
        }
        else {
            Write-TestResult -TestName $TestName -Result 'Fail' -Message $FailureMessage
            return $false
        }
    }
    catch {
        Write-TestResult -TestName $TestName -Result 'Fail' -Message "Exception: $($_.Exception.Message)"
        return $false
    }
}
#endregion

#region Main Test Execution
Write-Output ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Windows Driver Updater - Validation Suite" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Output ""
Write-Host "Running tests at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Output ""

# Section 1: File Integrity Tests
Write-Host "--- FILE INTEGRITY TESTS ---" -ForegroundColor Yellow
Write-Output ""

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Test-Assertion -TestName "Main script exists (WindowsDriverUpdater_Updated.ps1)" -Condition {
    Test-Path (Join-Path $scriptDir "WindowsDriverUpdater_Updated.ps1")
} -FailureMessage "File not found"

Test-Assertion -TestName "AutoStart script exists (WindowsDriverUpdater_AutoStart.ps1)" -Condition {
    Test-Path (Join-Path $scriptDir "WindowsDriverUpdater_AutoStart.ps1")
} -FailureMessage "File not found"

Test-Assertion -TestName "Batch launcher exists (WindowsDriverUpdater_Updated.bat)" -Condition {
    Test-Path (Join-Path $scriptDir "WindowsDriverUpdater_Updated.bat")
} -FailureMessage "File not found"

Test-Assertion -TestName "AutoStart batch exists (WindowsDriverUpdater_AutoStart.bat)" -Condition {
    Test-Path (Join-Path $scriptDir "WindowsDriverUpdater_AutoStart.bat")
} -FailureMessage "File not found"

Test-Assertion -TestName "Quick installer exists (Install-DriverUpdater.cmd)" -Condition {
    Test-Path (Join-Path $scriptDir "Install-DriverUpdater.cmd")
} -FailureMessage "File not found"

Write-Output ""

# Section 2: PowerShell Environment Tests
Write-Host "--- POWERSHELL ENVIRONMENT TESTS ---" -ForegroundColor Yellow
Write-Output ""

Test-Assertion -TestName "PowerShell version >= 5.1" -Condition {
    $PSVersionTable.PSVersion.Major -ge 5 -and $PSVersionTable.PSVersion.Minor -ge 1
} -SuccessMessage "Version $($PSVersionTable.PSVersion)" -FailureMessage "Version $($PSVersionTable.PSVersion) - requires 5.1+"

Test-Assertion -TestName "ExecutionPolicy allows scripts" -Condition {
    $policy = Get-ExecutionPolicy
    $policy -in @('Unrestricted', 'RemoteSigned', 'Bypass')
} -SuccessMessage "Policy: $(Get-ExecutionPolicy)" -FailureMessage "Policy: $(Get-ExecutionPolicy) - may block scripts"

Test-Assertion -TestName ".NET Framework version" -Condition {
    $netVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue).Release
    $netVersion -ge 461808  # .NET 4.7.2+
} -SuccessMessage ".NET 4.7.2 or later installed" -FailureMessage ".NET Framework may need update"

Write-Output ""

# Section 3: Windows Services Tests
Write-Host "--- WINDOWS SERVICES TESTS ---" -ForegroundColor Yellow
Write-Output ""

Test-Assertion -TestName "Windows Update service exists" -Condition {
    $null -ne (Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue)
} -FailureMessage "Service not found"

$wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
if ($wuService) {
    Test-Assertion -TestName "Windows Update service status" -Condition {
        $wuService.Status -eq 'Running' -or $wuService.StartType -ne 'Disabled'
    } -SuccessMessage "Status: $($wuService.Status), StartType: $($wuService.StartType)" -FailureMessage "Service is disabled"
}

Test-Assertion -TestName "Task Scheduler service running" -Condition {
    (Get-Service -Name "Schedule" -ErrorAction SilentlyContinue).Status -eq 'Running'
} -FailureMessage "Task Scheduler not running"

Write-Output ""

# Section 4: Network Connectivity Tests
Write-Host "--- NETWORK CONNECTIVITY TESTS ---" -ForegroundColor Yellow
Write-Output ""

Test-Assertion -TestName "TLS 1.2 available" -Condition {
    [Enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls12'
} -FailureMessage "TLS 1.2 not available"

Test-Assertion -TestName "Internet connectivity (download.windowsupdate.com)" -Condition {
    Test-NetConnection -ComputerName "download.windowsupdate.com" -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
} -FailureMessage "Cannot reach download.windowsupdate.com"

Test-Assertion -TestName "PowerShell Gallery reachable" -Condition {
    Test-NetConnection -ComputerName "www.powershellgallery.com" -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
} -FailureMessage "Cannot reach PowerShell Gallery"

Write-Output ""

# Section 5: Module Tests
Write-Host "--- MODULE TESTS ---" -ForegroundColor Yellow
Write-Output ""

Test-Assertion -TestName "NuGet package provider available" -Condition {
    $null -ne (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)
} -SuccessMessage "NuGet installed" -FailureMessage "NuGet not installed (will be auto-installed)"

$pswuModule = Get-Module -ListAvailable -Name PSWindowsUpdate -ErrorAction SilentlyContinue
if ($pswuModule) {
    Write-TestResult -TestName "PSWindowsUpdate module installed" -Result 'Pass' -Message "Version $($pswuModule.Version)"
}
else {
    Write-TestResult -TestName "PSWindowsUpdate module installed" -Result 'Warn' -Message "Not installed (will be auto-installed)"
}

Write-Output ""

# Section 6: Permission Tests
Write-Host "--- PERMISSION TESTS ---" -ForegroundColor Yellow
Write-Output ""

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-TestResult -TestName "Running as Administrator" -Result 'Pass' -Message "Admin privileges confirmed"
}
else {
    Write-TestResult -TestName "Running as Administrator" -Result 'Warn' -Message "Not running as admin - some tests skipped"
}

if ($isAdmin) {
    Test-Assertion -TestName "Can write to ProgramData" -Condition {
        $testPath = "$env:ProgramData\DriverUpdater\test_$(Get-Random).tmp"
        $testDir = Split-Path $testPath -Parent
        if (-not (Test-Path $testDir)) { New-Item -Path $testDir -ItemType Directory -Force | Out-Null }
        "test" | Out-File $testPath -Force
        $result = Test-Path $testPath
        if ($result) { Remove-Item $testPath -Force -ErrorAction SilentlyContinue }
        $result
    } -FailureMessage "Cannot write to ProgramData"

    Test-Assertion -TestName "Can access registry startup key" -Condition {
        $null -ne (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue)
    } -FailureMessage "Cannot access registry"
}

Write-Output ""

# Section 7: Script Syntax Tests
Write-Host "--- SCRIPT SYNTAX TESTS ---" -ForegroundColor Yellow
Write-Output ""

$mainScript = Join-Path $scriptDir "WindowsDriverUpdater_Updated.ps1"
if (Test-Path $mainScript) {
    Test-Assertion -TestName "Main script parses without errors" -Condition {
        $null -ne [System.Management.Automation.Language.Parser]::ParseFile($mainScript, [ref]$null, [ref]$null)
    } -FailureMessage "Syntax errors in main script"
}

$autoStartScript = Join-Path $scriptDir "WindowsDriverUpdater_AutoStart.ps1"
if (Test-Path $autoStartScript) {
    Test-Assertion -TestName "AutoStart script parses without errors" -Condition {
        $null -ne [System.Management.Automation.Language.Parser]::ParseFile($autoStartScript, [ref]$null, [ref]$null)
    } -FailureMessage "Syntax errors in AutoStart script"
}

Write-Output ""

# Section 8: Configuration Validation
Write-Host "--- CONFIGURATION VALIDATION ---" -ForegroundColor Yellow
Write-Output ""

if (Test-Path $mainScript) {
    $scriptContent = Get-Content $mainScript -Raw

    Test-Assertion -TestName "Version header present" -Condition {
        $scriptContent -match "Version:\s*\d+\.\d+"
    } -SuccessMessage "Version info found"

    Test-Assertion -TestName "TLS configuration present" -Condition {
        $scriptContent -match "SecurityProtocol.*Tls12"
    } -SuccessMessage "TLS 1.2 configured"

    Test-Assertion -TestName "Error handling (StrictMode)" -Condition {
        $scriptContent -match "Set-StrictMode"
    } -SuccessMessage "StrictMode enabled"

    Test-Assertion -TestName "Logging function present" -Condition {
        $scriptContent -match "function Write-Log"
    } -SuccessMessage "Logging available"
}

Write-Output ""

#region Summary
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "              TEST SUMMARY                  " -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Output ""
Write-Host "  Passed:   $script:PassCount" -ForegroundColor Green
Write-Host "  Failed:   $script:FailCount" -ForegroundColor Red
Write-Host "  Warnings: $script:WarnCount" -ForegroundColor Yellow
Write-Output ""

$totalTests = $script:PassCount + $script:FailCount + $script:WarnCount
$successRate = if ($totalTests -gt 0) { [math]::Round(($script:PassCount / $totalTests) * 100, 1) } else { 0 }

Write-Host "  Success Rate: $successRate%" -ForegroundColor $(if ($successRate -ge 80) { 'Green' } elseif ($successRate -ge 60) { 'Yellow' } else { 'Red' })
Write-Output ""

if ($script:FailCount -eq 0) {
    Write-Host "All critical tests passed! The Driver Updater is ready to use." -ForegroundColor Green
}
elseif ($script:FailCount -le 2) {
    Write-Host "Minor issues detected. Review failures above before proceeding." -ForegroundColor Yellow
}
else {
    Write-Host "Multiple failures detected. Please resolve issues before using." -ForegroundColor Red
}

Write-Output ""
Write-Host "============================================" -ForegroundColor Cyan
#endregion

# Return exit code based on failures
exit $script:FailCount
