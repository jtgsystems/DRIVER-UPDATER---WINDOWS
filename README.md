# Windows Comprehensive Updater

A powerful PowerShell script that automatically installs ALL Windows updates including security updates, critical updates, drivers, feature packs, quality updates, optional updates, and third-party updates - plus WinGet packages.

## 🚀 Features

- **Automatic Admin Elevation**: Script automatically relaunches with administrator privileges
- **ALL Windows Updates**: Installs every available Windows update - security, critical, drivers, feature packs, quality updates, optional updates, and third-party updates
- **State Persistence**: Tracks progress between reboots to prevent duplicate work
- **Reboot Loop Prevention**: Maximum 5 reboot cycles with state tracking
- **Non-Blocking Automation**: Detects interactive vs automated execution
- **Timeout Protection**: Long operations properly handled
- **Selective Updates**: Configurable to update drivers only, critical updates, or everything
- **Lock File Management**: Prevents multiple instances from running simultaneously
- **Comprehensive Logging**: Detailed logging with automatic rotation at 5MB
- **🎵 Darude Sandstorm Alerts**: Plays iconic beat pattern when user action is required (UAC prompts, exit confirmation)

## 📋 What Gets Updated

### ALL Windows Updates (Default Mode = "All")
- **Security Updates** - Critical security patches and vulnerability fixes
- **Critical Updates** - System stability and reliability improvements
- **Quality Updates** - Monthly rollups and cumulative updates
- **Feature Updates** - Major Windows version updates (e.g., 22H2, 23H1)
- **Driver Updates** - All hardware drivers (graphics, audio, network, chipset, etc.)
- **Optional Updates** - Additional drivers, language packs, and features
- **Microsoft Updates** - Office, .NET Framework, and other Microsoft products
- **Third-Party Updates** - Updates from hardware manufacturers and software vendors distributed through Windows Update

### Additional Components (When updateMode = "All")
- **WinGet Packages** - Desktop applications (with exclusion list support)

## 🔧 Requirements

- Windows 10/11 (any edition)
- PowerShell 5.1 or higher
- Internet connection
- Administrator privileges (script will auto-elevate)

## 💻 Usage

### Simple Execution
1. Right-click on `new.ps1`
2. Select "Run with PowerShell"
3. Approve the UAC prompt when Darude Sandstorm plays 🎵
4. Script will automatically handle everything

### Command Line Execution
```powershell
# Basic execution (ALL Windows updates by default)
.\new.ps1

# For automated/scheduled tasks
powershell.exe -NoProfile -ExecutionPolicy Bypass -NonInteractive -File "new.ps1"
```

### Scheduled Task Setup
The script automatically creates a scheduled task if a reboot is required, ensuring updates continue after restart.

## 🛡️ Safety Features

- **No Infinite Loops**: Maximum 5 reboot cycles with state tracking
- **Error Recovery**: Continues operation even if individual updates fail
- **COM Object Cleanup**: Proper cleanup prevents memory leaks
- **Internet Check**: Verifies connectivity before attempting updates
- **Module Validation**: Ensures required PowerShell modules are available
- **Timeout Protection**: 30-minute timeout on system scans (SFC/DISM)
- **Lock File**: Prevents concurrent executions

## 📁 Files Generated

- `WindowsUpdateLog.txt` - Detailed log of all operations
- `UpdateState.json` - Temporary state file (deleted after completion)
- `UpdateScript.lock` - Lock file to prevent concurrent runs

## ⚙️ Configuration

Edit these variables at the top of the script to customize behavior:

```powershell
# Update mode - Options: "Drivers", "Critical", "All"
$script:updateMode = "All"  # Default: installs ALL available Windows updates

# Maximum reboot cycles (default: 5)
$MAX_REBOOT_CYCLES = 5

# WinGet packages to exclude from updates
$WINGET_EXCLUSIONS = @("PackageID1", "PackageID2")
```

## 🎵 Audio Notifications

The script plays the Darude Sandstorm beat pattern when user interaction is required:
- UAC elevation prompt
- Script completion (when running interactively)
- Any time user confirmation is needed

This ensures you never miss important prompts that require your attention.

## 🔍 How It Works

1. **Initialization**
   - Checks for admin privileges (auto-elevates with 🎵 if needed)
   - Verifies internet connectivity with timeout
   - Loads previous state if recovering from reboot

2. **Update Detection**
   - Registers Microsoft Update Service (enables third-party updates)
   - Searches for ALL available Windows updates including third-party
   - Categorizes updates: Security, Critical, Drivers, Feature Packs, Quality Updates, Third-Party
   - Lists all available updates with sizes

3. **Installation**
   - Installs ALL updates one by one with progress tracking
   - Saves state after each successful install
   - Falls back to COM interface if PSWindowsUpdate unavailable

4. **Reboot Handling**
   - Checks for pending reboots
   - Creates scheduled task for continuation
   - Preserves state across reboots
   - Resumes from last successful point

5. **Cleanup**
   - Removes scheduled task when complete
   - Clears state file
   - Archives logs if over 5MB

## 🐛 Troubleshooting

### Script Won't Run
- Ensure execution policy allows scripts: `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`
- Right-click and "Run with PowerShell" instead of double-clicking

### Updates Not Found
- Check `WindowsUpdateLog.txt` for detailed information
- Ensure Windows Update service is running
- Try running Windows Update manually first to sync catalog

### Script Hangs
- Look for lock file and delete if stale
- Check Task Manager for PowerShell processes
- Check if Windows Update is downloading large updates

### Reboot Loop
- Script automatically stops after 5 reboots
- Delete `UpdateState.json` to reset counter
- Check log for specific failing update

## 📝 Version History

### Version 2.1 (Current)
- **Added third-party update support through Microsoft Update service**
- Enhanced to detect and install updates from hardware manufacturers and software vendors
- Improved categorization to identify third-party updates separately
- Updated COM interface to explicitly use Microsoft Update service for third-party updates
- **Removed system integrity checks (SFC/DISM)** - Was too slow (30+ minutes timeout)

### Version 2.0
- Complete rewrite with all critical issues fixed
- **Now installs ALL Windows updates, not just drivers**
- Added state persistence and reboot loop prevention
- Includes all update categories: Security, Critical, Drivers, Feature Packs, Quality Updates
- Added timeout protection for all operations
- Fixed COM object cleanup and memory leaks
- Added non-interactive mode for automation
- Dynamic progress tracking
- Comprehensive error handling
- Added Darude Sandstorm audio alerts for user actions

### Version 1.0 (Original)
- Initial implementation
- Basic update functionality

## 📄 License

This script is provided as-is for internal use. Modify as needed for your environment.

## 🤝 Support

For issues or improvements, check the logs at:
- `WindowsUpdateLog.txt` in the script directory

## ⚠️ Important Notes

- This script is designed for drivers specifically, not general Windows updates
- Always backup important data before running system updates
- The script will automatically handle reboots when required
- For production environments, test in a sandbox first
- Logs are automatically rotated at 5MB to prevent disk space issues
- Listen for Darude Sandstorm 🎵 to know when user action is needed