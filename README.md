# Windows Driver Updater

A comprehensive PowerShell script for automatically updating Windows drivers and system components with enterprise-grade error handling and automation support.

## 🚀 Features

- **Automatic Admin Elevation**: Script automatically relaunches with administrator privileges
- **Driver-Specific Updates**: Correctly filters and installs only driver updates using proper Windows Update API
- **State Persistence**: Tracks progress between reboots to prevent duplicate work
- **Reboot Loop Prevention**: Maximum 5 reboot cycles with state tracking
- **Non-Blocking Automation**: Detects interactive vs automated execution
- **Timeout Protection**: All long operations have configurable timeouts
- **Selective Updates**: Configurable to update drivers only, critical updates, or everything
- **Lock File Management**: Prevents multiple instances from running simultaneously
- **Comprehensive Logging**: Detailed logging with automatic rotation at 5MB
- **🎵 Darude Sandstorm Alerts**: Plays iconic beat pattern when user action is required (UAC prompts, exit confirmation)

## 📋 What Gets Updated

### Driver Updates (Default Mode)
- Display/Graphics drivers (NVIDIA, AMD, Intel)
- Audio drivers (Realtek, etc.)
- Network adapters
- Chipset drivers
- Storage controllers
- All hardware drivers available through Windows Update

### Optional Components (Configurable)
- Critical Windows security updates
- WinGet packages (with exclusion list)
- System integrity checks (SFC/DISM)

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
# Basic execution (drivers only)
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
$script:updateMode = "Drivers"

# Maximum reboot cycles (default: 5)
$MAX_REBOOT_CYCLES = 5

# Timeout for SFC/DISM operations in minutes (default: 30)
$SFC_DISM_TIMEOUT_MINUTES = 30

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

2. **Driver Detection**
   - Registers Microsoft Update Service
   - Searches specifically for driver updates using category GUID
   - Lists all available drivers with sizes

3. **Installation**
   - Installs drivers one by one with progress tracking
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
- Check if SFC/DISM is running (can take 30+ minutes)
- Look for lock file and delete if stale
- Check Task Manager for PowerShell processes

### Reboot Loop
- Script automatically stops after 5 reboots
- Delete `UpdateState.json` to reset counter
- Check log for specific failing update

## 📝 Version History

### Version 2.0 (Current)
- Complete rewrite with all critical issues fixed
- Added state persistence and reboot loop prevention
- Implemented proper driver-specific filtering
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