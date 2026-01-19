# VHD(X) Cleanup Tool

A PowerShell CLI that scans a folder of VHD/VHDX images, mounts each image, deletes specified paths, and unmounts safely with detailed logging and performance metrics.

## Prerequisites

- Windows with Storage PowerShell module (built-in to Windows).
- Administrative privileges (required for mounting/unmounting disk images).
- Access to the target folder containing VHD/VHDX files.

**Note:** This script uses `Mount-DiskImage` (same as Windows Disk Management), so Hyper-V Platform is **not required**.

## Usage

```powershell
.\src\vhdx-cleanup.ps1 -TargetFolder "C:\Vhdx" -DeletePath "Windows\Temp","Users\Public\Downloads\stale.log"
```

### Parameters

- `TargetFolder`: Root folder to scan recursively for `.vhd` and `.vhdx` files.
- `DeletePath`: One or more paths to delete inside each mounted image. Paths are
  treated as relative to the mounted volume root (for example, `Windows\Temp`).
- `-ShowDetails`: Show detailed operational output including work list, per-path results,
  summary, and performance metrics. Without this parameter, only errors are displayed
  on console (all details are still logged to file).
- `-Verbose`: Enable verbose/debug logging. Shows system information banner and DEBUG
  level messages. Can be combined with `-ShowDetails` for full visibility.

### Environment Variables

You can use environment variables in `DeletePath` entries using either syntax:
- PowerShell: `$env:VARIABLE` (e.g., `Users\$env:USERNAME\AppData\Local\Temp`)
- CMD-style: `%VARIABLE%` (e.g., `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache`)

## Examples

```powershell
# Clean temp folders across all images
.\src\vhdx-cleanup.ps1 -TargetFolder "D:\Images" -DeletePath "Windows\Temp","Temp"

# Remove a specific file from each image
.\src\vhdx-cleanup.ps1 -TargetFolder "C:\Vhdx" -DeletePath "Users\Public\Downloads\stale.log"

# Use environment variables in paths
.\src\vhdx-cleanup.ps1 -TargetFolder "C:\Vhdx" -DeletePath "Users\$env:USERNAME\AppData\Local\Temp","%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache"

# Show detailed operational output
.\src\vhdx-cleanup.ps1 -TargetFolder "C:\Vhdx" -DeletePath "Temp" -ShowDetails

# Enable verbose logging (system info + debug messages)
.\src\vhdx-cleanup.ps1 -TargetFolder "C:\Vhdx" -DeletePath "Temp" -Verbose

# Combine both for full visibility
.\src\vhdx-cleanup.ps1 -TargetFolder "C:\Vhdx" -DeletePath "Temp" -Verbose -ShowDetails

# Delete multiple paths (all paths are processed even if some fail)
.\src\vhdx-cleanup.ps1 -TargetFolder "C:\Vhdx" -DeletePath "Level1\Level2","Level1-1","Temp" -ShowDetails
```

## Logs and Output

### Log Files

- A log file is created in the target folder: `vhdx-cleanup-<timestamp>.log`
- Log rotation: Automatically keeps the last 10 log files (older logs are removed)
- Log levels: TRACE, DEBUG, INFO, SUCCESS, WARN, ERROR
- Timestamps: UTC format with millisecond precision

### Console Output

**Output Control:**
- **Without `-ShowDetails`**: Only ERROR messages are displayed on console (minimal output)
- **With `-ShowDetails`**: Shows detailed operational output (work list, per-path results, summary, performance)
- **With `-Verbose`**: Shows system information banner and DEBUG level messages
- **With both**: Full visibility (system info + detailed operations + debug messages)

**Colored output** for better visibility:
- `[X]` Red - Errors (always shown)
- `[!]` Yellow - Warnings (shown with `-ShowDetails`)
- `[+]` Green - Success (shown with `-ShowDetails`)
- `[i]` White - Info (shown with `-ShowDetails`)
- `[D]` DarkGray - Debug (with `-Verbose`)
- `[T]` Gray - Trace (with `-Verbose`)

**Note:** All information is always logged to the log file regardless of console output settings.

### Performance Metrics

Each run includes:
- Total execution time
- Average time per image
- Per-image processing duration
- Start and end timestamps

### Detailed Reporting

- Per-image results with deletion counts (Deleted, Missing, Failed)
- Per-path results showing which paths succeeded or failed
- Summary statistics with totals
- Error messages for failed operations

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Cleanup completed successfully (all images processed, all paths deleted). |
| 10 | Invalid input arguments (missing folder, empty paths, or missing prerequisites). |
| 20 | Cleanup failed for all work items (all images failed to process). |
| 30 | Cleanup completed with failed work items (some images succeeded, some failed, or some paths failed to delete). |
| 40 | Cleanup failed due to an unhandled exception (fatal error). |

## Operational Notes

- **Multiple paths**: All specified paths are processed even if some fail. The script continues with remaining paths.
- **Missing paths**: Missing delete paths are logged as warnings and skipped (not an error).
- **Failed paths**: If a path fails to delete (e.g., locked file), it's logged as an error but processing continues.
- **Failed images**: Failed images are logged and skipped so the batch can continue processing other images.
- **Partial success**: Images are marked as "PartiallyCleaned" if some paths succeeded and some failed.
- **Typical batch size**: Small batches (1–5 images) are typical, but the script handles any number.
- **Performance**: Each image is processed sequentially with timing information logged.

## Features

- ✅ **No Hyper-V required** - Uses Windows Storage API (same as Disk Management)
- ✅ **Environment variable support** - Use `$env:VAR` or `%VAR%` in paths
- ✅ **Multiple path deletion** - Process all paths even if some fail
- ✅ **Enhanced logging** - Colored console output, log rotation, performance metrics
- ✅ **Detailed reporting** - Per-image and per-path results with error details
- ✅ **Output control** - `-ShowDetails` parameter to control detailed output visibility
- ✅ **Verbose mode** - Debug logging with `-Verbose` parameter (shows system info)
- ✅ **Safe error handling** - Continues processing even when errors occur
