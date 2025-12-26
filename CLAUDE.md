# CLAUDE.md - Windows Driver Updater Tool

## Project Overview

The **Windows Driver Updater Tool** is an enterprise-grade PowerShell automation solution designed to streamline Windows driver and update installation on new and existing systems. This tool provides fully autonomous operation, USB deployment capabilities, and intelligent self-management features.

## Architecture

### Core Components

1. **WindowsDriverUpdater_Updated.ps1** (30KB, 836 lines)
   - Main driver update engine with comprehensive feature set
   - Supports both interactive and silent operation modes
   - Handles drivers, Windows updates, and application updates
   - Version: 4.4 (Last Updated: 2025-12-19)

2. **WindowsDriverUpdater_AutoStart.ps1** (20KB, 596 lines)
   - Self-installing variant with auto-startup capabilities
   - State persistence across system reboots
   - Automatic self-removal after completion
   - Dual startup registration (Registry + Task Scheduler)
   - Version: 4.4 (Last Updated: 2025-12-19)

3. **Batch Launchers**
   - `Install-DriverUpdater.cmd` - Quick installer with auto-elevation
   - `WindowsDriverUpdater_AutoStart.bat` - Menu-driven interface launcher
   - `WindowsDriverUpdater_Updated.bat` - Legacy script launcher
   - `launch driver updater.bat` - Alternative launcher

4. **Test-DriverUpdater.ps1** (12KB, 318 lines)
   - Comprehensive validation suite
   - Tests file integrity, environment, services, network, and permissions
   - Non-destructive testing (no system changes)

## Key Features

### Update Management
- **Windows Updates**: Security, critical, rollups, and updates
- **Driver Updates**: From Windows Update with signature validation
- **App Updates**: WinGet packages and Microsoft Store apps
- **Component Updates**: Windows Defender definitions and PowerShell modules
- **Feature Upgrade Exclusion**: Explicitly blocks Windows version upgrades (e.g., Win10 to Win11)

### Automation & Reliability
- **Auto-Startup**: Dual registration via Registry and Task Scheduler
- **State Persistence**: JSON-based state tracking across reboots
- **USB Detection**: Automatic copy to local drive when run from USB
- **Smart Completion**: Self-removes after 3 consecutive runs with no updates
- **Retry Logic**: Exponential backoff for failed operations (max 3 retries)
- **Reboot Management**: Graceful handling of required system restarts

### Safety Features
- **Driver Backup**: Exports existing drivers before updates
- **System Restore Points**: Optional creation before changes
- **Signature Validation**: Verifies driver digital signatures
- **Preview/Beta Filtering**: Excludes non-production updates
- **Comprehensive Logging**: Detailed audit trail with rotation
- **TLS Security**: Enforces TLS 1.2/1.3 for downloads

## Technical Details

### System Requirements
- **OS**: Windows 10 (1809+), Windows 11, or Server 2016+
- **PowerShell**: Version 5.1 or later
- **Privileges**: Administrator rights required
- **Network**: Internet connectivity required
- **Disk Space**: 500MB minimum (more for driver backups)
- **.NET Framework**: 4.7.2+ recommended

### Dependencies
- **PSWindowsUpdate Module**: Automatically installed from PowerShell Gallery
- **NuGet Package Provider**: Auto-installed if missing
- **Windows Update Service**: Must be enabled
- **Task Scheduler Service**: Required for auto-start functionality

### File Locations
```
%ProgramData%\DriverUpdater\          # Working directory
├── DriverUpdater.state                # State persistence file
├── DriverUpdater_AutoStart.log        # Main log file
└── DriverBackups\                     # Driver backup directory
    └── YYYYMMDD_HHMMSS\              # Timestamped backups
```

### Registry & Scheduled Tasks
- **Registry Key**: `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- **Registry Value**: `DriverUpdaterAutoStart`
- **Scheduled Task**: `DriverUpdaterAutoStart` (runs as SYSTEM)

## Configuration

### Main Script Configuration (`WindowsDriverUpdater_Updated.ps1`)
```powershell
$script:Config = @{
    LogPath              = "DriverUpdaterLog.txt"
    ModuleName           = "PSWindowsUpdate"
    InternetTestTarget   = "download.windowsupdate.com"
    MSUpdateServiceId    = "7971f918-a847-4430-9279-4a52d1efe18d"
    MaxRetries           = 3
    RetryDelaySeconds    = 5
    MaxLogSize           = 10MB
    LogRetentionDays     = 30
    UpdateCategories     = @("Drivers", "CriticalUpdates", "SecurityUpdates",
                             "UpdateRollups", "Updates")
    ExcludedTitlePatterns = @("*Feature update to Windows*",
                              "*Upgrade to Windows*",
                              "*Windows 11*")
    UpdateApps           = $true
    UpdateStoreApps      = $true
    UpdateDefender       = $true
    UpdatePowerShellModules = $true
}
```

### AutoStart Script Configuration
```powershell
$script:Config = @{
    ScriptName                    = "WindowsDriverUpdater_AutoStart"
    StartupRegPath                = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    StartupTaskName               = "DriverUpdaterAutoStart"
    LogFileName                   = "DriverUpdater_AutoStart.log"
    StateFile                     = "DriverUpdater.state"
    MaxRetries                    = 3
    RetryDelaySeconds             = 5
    ConsecutiveNoUpdatesThreshold = 3  # Runs before self-removal
}
```

## Usage Examples

### Quick Start
```cmd
# Run the quick installer (auto-elevates)
Install-DriverUpdater.cmd
```

### PowerShell Direct Execution
```powershell
# Interactive mode with all features
.\WindowsDriverUpdater_Updated.ps1

# Silent mode with restore point
.\WindowsDriverUpdater_Updated.ps1 -Silent -CreateRestorePoint

# Auto-install with specific filter
.\WindowsDriverUpdater_Updated.ps1 -AutoInstall -DriverFilter "Intel,AMD"

# Skip backup for faster execution
.\WindowsDriverUpdater_Updated.ps1 -SkipBackup -MaxUpdates 5

# Force install unsigned drivers (use with caution)
.\WindowsDriverUpdater_Updated.ps1 -Force
```

### AutoStart Script
```powershell
# Install and configure auto-start
.\WindowsDriverUpdater_AutoStart.ps1

# Check for updates without installing
.\WindowsDriverUpdater_AutoStart.ps1 -CheckOnly

# Remove from startup
.\WindowsDriverUpdater_AutoStart.ps1 -RemoveFromStartup
```

### USB Deployment
```cmd
1. Copy all files to USB drive
2. Insert USB into target system
3. Run Install-DriverUpdater.cmd
4. Remove USB after installation starts (script auto-copies to local drive)
```

## Workflow

### AutoStart Lifecycle
```
1. Initial Run
   ├── Detect USB execution → Copy to local if needed
   ├── Install PSWindowsUpdate module
   ├── Check for updates
   ├── Install updates if found
   ├── Register to startup (Registry + Task)
   └── Save state to JSON file

2. Subsequent Runs (at each startup)
   ├── Load previous state
   ├── Check for new updates
   ├── Install updates → Reset no-update counter
   │   OR
   ├── No updates → Increment counter
   └── Save updated state

3. Completion (after 3 runs with no updates)
   ├── Remove from startup (Registry + Task)
   ├── Delete state file
   ├── Schedule cleanup task
   └── Exit
```

## Security Considerations

### Built-in Protections
1. **Admin Enforcement**: Mandatory administrator privileges check
2. **Path Validation**: Prevents command injection in startup registration
3. **TLS Hardening**: Enforces modern TLS protocols (1.2/1.3)
4. **Driver Signature Validation**: Verifies authentic driver sources
5. **Audit Logging**: Comprehensive operation logging with Event Log fallback
6. **No Interactive Elevation**: Uses Scheduled Task cleanup instead of temp scripts

### Security Improvements (v4.1)
- Fixed potential command injection vulnerability in startup registration
- Replaced insecure temp script execution with scheduled task cleanup
- Added path validation before startup registration
- Modernized WMI calls to CIM (more secure)

## Error Handling

### Retry Mechanism
- Maximum 3 retry attempts for critical operations
- 5-second delay between retries with exponential backoff
- Comprehensive error logging for all failures

### Fallback Strategies
- Log file write failure → Event Log fallback
- Module installation failure → Retry on next run
- Internet connectivity issues → Graceful degradation
- State file corruption → Auto-recreation with defaults

## Logging & Monitoring

### Log Format
```
2024-01-15 10:30:45 - [Info] Message
2024-01-15 10:30:46 - [Success] Operation successful
2024-01-15 10:30:47 - [Warning] Non-critical issue
2024-01-15 10:30:48 - [Error] Critical failure
```

### Log Rotation
- Maximum log size: 10MB
- Retention period: 30 days
- Automatic archiving with timestamps

### State File Structure
```json
{
    "InstallCount": 5,
    "LastRun": "2024-01-15 10:32:17",
    "ConsecutiveNoUpdates": 1,
    "IsComplete": false
}
```

### Monitoring Commands
```powershell
# View current state
Get-Content "$env:ProgramData\DriverUpdater\DriverUpdater.state" | ConvertFrom-Json

# Monitor log in real-time
Get-Content "$env:ProgramData\DriverUpdater\DriverUpdater_AutoStart.log" -Wait -Tail 10

# Check startup registration
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" |
    Select-Object DriverUpdaterAutoStart

# View scheduled task
Get-ScheduledTask -TaskName "DriverUpdaterAutoStart"

# Check Event Log entries
Get-EventLog -LogName Application -Source "DriverUpdater" -Newest 20
```

## Testing & Validation

### Run Validation Suite
```powershell
# Basic validation
.\Test-DriverUpdater.ps1

# Verbose output
.\Test-DriverUpdater.ps1 -Verbose
```

### Test Coverage
- File integrity (5 tests)
- PowerShell environment (3 tests)
- Windows services (3 tests)
- Network connectivity (3 tests)
- Module availability (2 tests)
- Permissions (3 tests)
- Script syntax (2 tests)
- Configuration validation (4 tests)

## Troubleshooting

### Common Issues

**Issue**: "Administrator privileges required"
```powershell
# Solution: Right-click and "Run as administrator" or use Install-DriverUpdater.cmd
```

**Issue**: "No internet connection detected"
```powershell
# Check Windows Update service
Get-Service wuauserv | Start-Service

# Test connectivity
Test-NetConnection download.windowsupdate.com -Port 443
```

**Issue**: "PSWindowsUpdate module installation failed"
```powershell
# Manual installation
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -Force
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope AllUsers
```

**Issue**: "Script not running at startup"
```powershell
# Verify Registry entry
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "DriverUpdaterAutoStart"

# Check Scheduled Task
Get-ScheduledTask -TaskName "DriverUpdaterAutoStart" | Get-ScheduledTaskInfo

# Re-add to startup
.\WindowsDriverUpdater_AutoStart.ps1
```

### Diagnostic Commands
```powershell
$diag = @{
    OS = Get-CimInstance Win32_OperatingSystem | Select Caption, Version
    PowerShell = $PSVersionTable.PSVersion
    WUService = Get-Service wuauserv | Select Status, StartType
    Internet = Test-NetConnection download.windowsupdate.com -Port 443 -InformationLevel Quiet
    Modules = Get-Module -ListAvailable PSWindowsUpdate
    AdminRights = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
$diag | ConvertTo-Json -Depth 3
```

## Version History

### Version 4.4 (2025-12-19)
- Added app updates (WinGet and Microsoft Store)
- Added Defender definitions and PowerShell module updates
- Maintained feature-upgrade exclusion
- Updated auto-start logs to reflect new version

### Version 4.2 (2025-12-19)
- Prevented state/log recreation after self-removal
- Ensured log/state directories are created reliably under ProgramData
- Allowed driver updates without KB metadata to be processed
- Added TLS hardening to auto-start module installation
- Updated connectivity checks to use Microsoft endpoints

### Version 4.1 (2025-12-02)
- Fixed potential command injection vulnerability in startup registration
- Replaced insecure temp script execution with scheduled task cleanup
- Added path validation before startup registration
- Fixed incorrect filter logic in `Select-DriverUpdates`
- Fixed System Restore check logic
- Replaced deprecated `Get-WmiObject` with `Get-CimInstance`
- Renamed functions to use PowerShell approved verbs
- Added comprehensive documentation blocks
- Added `Test-DriverUpdater.ps1` validation script

### Version 4.0 (Previous)
- Initial Auto-Start Edition release
- USB deployment support
- Self-removal after completion

### Version 3.3 (Legacy)
- Core driver update functionality
- PSWindowsUpdate integration

## Performance Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| Startup Impact | < 5 seconds | Minimal boot time increase |
| Memory Usage | ~50-100 MB | During active updating |
| Network Usage | Variable | Depends on driver sizes |
| Average Runtime | 5-30 minutes | Per update session |
| Driver Install Rate | 1-3 min/driver | Includes validation |

## Best Practices

### Deployment
1. Test on non-production systems first
2. Verify network connectivity before deployment
3. Ensure Windows Update service is enabled
4. Back up system before running updates
5. Monitor logs after initial deployment

### Maintenance
1. Review logs periodically
2. Keep driver backups for 30 days minimum
3. Test restore points regularly
4. Update the tool when new versions are released
5. Monitor Event Logs for anomalies

### Security
1. Run only from trusted sources
2. Verify script signatures before execution
3. Review code changes in new versions
4. Use HTTPS for downloads (enforced by default)
5. Keep audit logs for compliance

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Repository Information

- **Repository**: git@github.com:jtgsystems/DRIVER-UPDATER---WINDOWS.git
- **Primary Branch**: (to be confirmed)
- **Language**: PowerShell 5.1+
- **Platform**: Windows 10/11, Server 2016+

## Contributing

### Reporting Issues
Include the following when reporting issues:
1. Full error message from log file
2. Relevant log excerpts (with timestamps)
3. System specifications (OS version, PowerShell version)
4. Steps to reproduce the issue
5. Output from `Test-DriverUpdater.ps1`

### Development Guidelines
- Follow PowerShell best practices and approved verbs
- Use `Set-StrictMode -Version Latest`
- Add comprehensive error handling
- Include documentation blocks for all functions
- Test on multiple Windows versions
- Validate with `Test-DriverUpdater.ps1` before committing

## Official Microsoft References

- [Windows Update Overview](https://support.microsoft.com/windows/update-windows-3c5ae7fc-9fb6-9af1-1984-b5e0412c556a)
- [Update Drivers Manually](https://support.microsoft.com/windows/update-drivers-manually-in-windows-ec62f46c-ff14-c91d-eead-d7126dc1f7b6)
- [Windows Update Error Reference](https://learn.microsoft.com/windows/deployment/update/windows-update-error-reference)
- [Windows Update Agent API (WUAPI)](https://learn.microsoft.com/windows/win32/api/wuapi/)
- [PSWindowsUpdate Module](https://www.powershellgallery.com/packages/PSWindowsUpdate)

## Acknowledgments

- Microsoft Windows Update team for the update infrastructure
- PSWindowsUpdate module contributors
- Community testers and contributors

---

**Document Version**: 1.0
**Last Updated**: 2025-12-26
**Maintained By**: Enterprise Tools Team
**For**: Windows System Administrators
