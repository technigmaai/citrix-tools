<#
.SYNOPSIS
Cleans specified paths inside VHD/VHDX images.

.DESCRIPTION
Scans the target folder for VHD/VHDX files, mounts each image, deletes
configured paths, logs results, and unmounts cleanly with exit codes.

.PARAMETER TargetFolder
Root folder to scan for VHD/VHDX images. Log output is written here.

.PARAMETER DeletePath
One or more relative paths inside each mounted image to remove. Paths are
resolved relative to the mounted volume root. Environment variables are supported
using PowerShell syntax ($env:VARIABLE) or CMD syntax (%VARIABLE%).

.PARAMETER ShowDetails
Show detailed operational output including work list, per-path results, summary,
and performance metrics. Without this parameter, only errors and warnings are
displayed on console (all details are still logged to file).

.PARAMETER Verbose
Enable verbose/debug logging. Shows system information banner and DEBUG level
messages. Can be combined with -ShowDetails for full visibility.

.EXAMPLE
.\vhdx-cleanup.ps1 -TargetFolder "D:\Images" -DeletePath "Windows\Temp","Users\Public\Downloads\stale.log"

.EXAMPLE
.\vhdx-cleanup.ps1 -TargetFolder "C:\Vhdx" -DeletePath "Temp" -ShowDetails

.EXAMPLE
.\vhdx-cleanup.ps1 -TargetFolder "C:\Vhdx" -DeletePath "Temp" -Verbose -ShowDetails

.EXAMPLE
.\vhdx-cleanup.ps1 -TargetFolder "D:\Images" -DeletePath "Users\$env:USERNAME\AppData\Local\Temp","%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache"

.NOTES
Requires administrative privileges (run PowerShell as Administrator) and Windows 
Storage PowerShell cmdlets such as Mount-DiskImage and Dismount-DiskImage 
(built-in to Windows).
DeletePath entries are relative to the mounted image root; missing paths are
logged and skipped.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$TargetFolder,

  [Parameter(Mandatory = $true)]
  [string[]]$DeletePath,

  [Parameter(Mandatory = $false)]
  [switch]$ShowDetails
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:VhdxCleanupLogFile = $null
$script:VhdxCleanupStartTime = $null
$script:VhdxCleanupLogLevel = 'ERROR'  # Default log level: Only show errors when ShowDetails is off
$script:VhdxCleanupLogRotationCount = 10  # Keep last 10 log files
$script:VhdxCleanupShowDetails = $false  # Control detailed operational output

function Test-VhdxCleanupAdminPrivileges {
  [CmdletBinding()]
  param()

  $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

  if (-not $isAdmin) {
    Write-Error "This script requires administrator privileges to mount and unmount disk images. Please run PowerShell as Administrator."
    return $false
  }

  return $true
}

function Test-VhdxCleanupStorageModule {
  [CmdletBinding()]
  param()

  # Storage module is built-in to Windows, but verify it's available
  $moduleName = 'Storage'
  if (-not (Get-Module -Name $moduleName -ListAvailable)) {
    Write-Error "Windows Storage PowerShell module is not available. This module should be built-in to Windows."
    return $false
  }

  if (-not (Get-Module -Name $moduleName)) {
    try {
      Import-Module -Name $moduleName -ErrorAction Stop
      Write-Verbose "Storage module imported successfully."
    } catch {
      Write-Error "Failed to import Storage module: $($_.Exception.Message)"
      return $false
    }
  }

  # Verify required cmdlets are available
  $requiredCmdlets = @('Mount-DiskImage', 'Dismount-DiskImage', 'Get-Disk', 'Get-Partition', 'Add-PartitionAccessPath')
  $missingCmdlets = @()

  foreach ($cmdlet in $requiredCmdlets) {
    if (-not (Get-Command -Name $cmdlet -ErrorAction SilentlyContinue)) {
      $missingCmdlets += $cmdlet
    }
  }

  if ($missingCmdlets.Count -gt 0) {
    Write-Error "Required cmdlets are missing: $($missingCmdlets -join ', '). These should be available in the Windows Storage module."
    return $false
  }

  return $true
}

function Get-VhdxCleanupExitCodeMapping {
  return @{
    Success = [pscustomobject]@{
      Code        = 0
      Description = 'Cleanup completed successfully.'
    }
    InvalidInput = [pscustomobject]@{
      Code        = 10
      Description = 'Invalid input arguments.'
    }
    RuntimeFailure = [pscustomobject]@{
      Code        = 20
      Description = 'Cleanup failed for all work items.'
    }
    PartialFailure = [pscustomobject]@{
      Code        = 30
      Description = 'Cleanup completed with failed work items.'
    }
    FatalError = [pscustomobject]@{
      Code        = 40
      Description = 'Cleanup failed due to an unhandled exception.'
    }
  }
}

function Write-VhdxCleanupExitCode {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [pscustomobject]$ExitCodeInfo,

    [string]$LogFile
  )

  $message = "Exit code $($ExitCodeInfo.Code): $($ExitCodeInfo.Description)"

  if ($LogFile) {
    Write-VhdxCleanupLog -Message $message -Level INFO -LogFile $LogFile
  } else {
    Write-Output $message
  }
}

function Test-VhdxCleanupInputs {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$TargetFolder,

    [Parameter(Mandatory = $true)]
    [string[]]$DeletePath
  )

  if (-not (Test-Path -Path $TargetFolder -PathType Container)) {
    Write-Error -ErrorAction Continue "Target folder does not exist or is not a directory: $TargetFolder"
    return $false
  }

  $nonEmptyDeletePaths = $DeletePath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
  if (-not $nonEmptyDeletePaths) {
    Write-Error -ErrorAction Continue "DeletePath must contain at least one non-empty entry."
    return $false
  }

  return $true
}

function Expand-EnvironmentVariables {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  $expanded = $Path
  
  # Expand PowerShell-style environment variables ($env:VARIABLE)
  # This uses PowerShell's string expansion which happens automatically, but we need to handle it explicitly
  # First, expand CMD-style %VARIABLE% syntax
  $expanded = [System.Environment]::ExpandEnvironmentVariables($expanded)
  
  # Then expand PowerShell-style $env:VARIABLE syntax
  # Use regex to find and replace $env:VARIABLE patterns
  while ($expanded -match '\$env:([A-Za-z_][A-Za-z0-9_]*)') {
    $varName = $matches[1]
    $varValue = [System.Environment]::GetEnvironmentVariable($varName)
    if ($null -ne $varValue) {
      # Replace the $env:VAR pattern with the actual value
      $expanded = $expanded -replace '\$env:' + [regex]::Escape($varName), $varValue
    } else {
      # If variable doesn't exist, leave it as-is and break to avoid infinite loop
      break
    }
  }
  
  return $expanded
}

function Normalize-DeletePaths {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$DeletePath
  )

  $normalized = New-Object System.Collections.Generic.List[string]
  $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

  foreach ($path in $DeletePath) {
    if ([string]::IsNullOrWhiteSpace($path)) {
      continue
    }

    # Expand environment variables in the path
    $expandedPath = Expand-EnvironmentVariables -Path $path
    $trimmedPath = $expandedPath.Trim()
    $relativePath = $trimmedPath.TrimStart('\', '/')

    if ([string]::IsNullOrWhiteSpace($relativePath)) {
      continue
    }

    if ($seen.Add($relativePath)) {
      $normalized.Add($relativePath)
    }
  }

  return $normalized.ToArray()
}

function New-VhdxCleanupLog {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$TargetFolder
  )

  $timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
  $logFile = Join-Path -Path $TargetFolder -ChildPath "vhdx-cleanup-$timestamp.log"
  New-Item -Path $logFile -ItemType File -Force | Out-Null

  # Rotate old log files (keep only the most recent N files)
  try {
    $oldLogs = Get-ChildItem -Path $TargetFolder -Filter "vhdx-cleanup-*.log" -File | 
      Sort-Object LastWriteTime -Descending | 
      Select-Object -Skip $script:VhdxCleanupLogRotationCount
    
    foreach ($oldLog in $oldLogs) {
      Remove-Item -Path $oldLog.FullName -Force -ErrorAction SilentlyContinue
    }
  } catch {
    # Ignore rotation errors
  }

  return $logFile
}

function Get-LogLevelPriority {
  param([string]$Level)
  
  $priorities = @{
    'TRACE' = 0
    'DEBUG' = 1
    'INFO'  = 2
    'SUCCESS' = 2
    'WARN'  = 3
    'ERROR' = 4
  }
  
  if ($priorities.ContainsKey($Level)) {
    return $priorities[$Level]
  } else {
    return 2
  }
}

function Get-ConsoleColor {
  param([string]$Level)
  
  $colors = @{
    'TRACE'  = 'Gray'
    'DEBUG'  = 'DarkGray'
    'INFO'   = 'White'
    'SUCCESS' = 'Green'
    'WARN'   = 'Yellow'
    'ERROR'  = 'Red'
  }
  
  if ($colors.ContainsKey($Level)) {
    return $colors[$Level]
  } else {
    return 'White'
  }
}

function Write-VhdxCleanupLog {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$Message,

    [ValidateSet('TRACE', 'DEBUG', 'INFO', 'SUCCESS', 'WARN', 'ERROR')]
    [string]$Level = 'INFO',

    [Parameter(Mandatory = $true)]
    [string]$LogFile,

    [switch]$NoNewline
  )

  # Check if we should log this level
  $currentPriority = Get-LogLevelPriority -Level $script:VhdxCleanupLogLevel
  $messagePriority = Get-LogLevelPriority -Level $Level
  
  if ($messagePriority -lt $currentPriority) {
    # Still write to log file, but skip console output
    try {
      $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
      $line = "[$timestamp] [$Level] $Message"
      Add-Content -Path $LogFile -Value $line -ErrorAction Stop
    } catch {
      # Ignore log file errors for filtered messages
    }
    return  # Skip console output if below threshold
  }

  $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
  $line = "[$timestamp] [$Level] $Message"

  # Write to log file (always, regardless of console output)
  try {
    Add-Content -Path $LogFile -Value $line -ErrorAction Stop
  } catch {
    # If log file write fails, at least try to output to console
    Write-Warning "Failed to write to log file: $($_.Exception.Message)"
  }

  # Write to console with color
  $color = Get-ConsoleColor -Level $Level
  $prefix = switch ($Level) {
    'ERROR'   { '[X]' }
    'WARN'    { '[!]' }
    'SUCCESS' { '[+]' }
    'INFO'    { '[i]' }
    'DEBUG'   { '[D]' }
    'TRACE'   { '[T]' }
    default   { '[*]' }
  }
  
  $consoleMessage = if ($Level -in @('ERROR', 'WARN', 'SUCCESS')) {
    "$prefix $Message"
  } else {
    $Message
  }

  if ($NoNewline) {
    Write-Host -Object $consoleMessage -ForegroundColor $color -NoNewline
  } else {
    Write-Host -Object $consoleMessage -ForegroundColor $color
  }
}

function Write-VhdxCleanupSummary {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [pscustomobject]$Summary,

    [Parameter(Mandatory = $true)]
    [string]$LogFile
  )

  $summaryLevel = if ($script:VhdxCleanupShowDetails) { 'INFO' } else { 'DEBUG' }

  Write-VhdxCleanupLog -Message "Summary:" -Level $summaryLevel -LogFile $LogFile
  Write-VhdxCleanupLog -Message "Log file: $($Summary.LogFile)" -Level $summaryLevel -LogFile $LogFile
  $totalMessage = "Totals - Completed: $($Summary.CompletedCount)"
  if ($Summary.PSObject.Properties.Name -contains 'PartiallyCleanedCount' -and $Summary.PartiallyCleanedCount -gt 0) {
    $totalMessage += " (including $($Summary.PartiallyCleanedCount) partially cleaned)"
  }
  $totalMessage += ", Failed: $($Summary.FailedCount), Skipped: $($Summary.SkippedCount)"
  Write-VhdxCleanupLog -Message $totalMessage -Level $summaryLevel -LogFile $LogFile

  $workItemsCount = if ($null -eq $Summary.WorkItems) { 0 } else { $Summary.WorkItems.Count }
  if ($workItemsCount -gt 0) {
    Write-VhdxCleanupLog -Message "Per-item results:" -Level $summaryLevel -LogFile $LogFile
    foreach ($item in $Summary.WorkItems) {
      # Safely get property values, defaulting to 0 if not present
      $deletedCount = 0
      $missingCount = 0
      $failedCount = 0
      if ($item.PSObject.Properties.Name -contains 'DeletedCount') {
        $deletedCount = $item.DeletedCount
      }
      if ($item.PSObject.Properties.Name -contains 'MissingCount') {
        $missingCount = $item.MissingCount
      }
      if ($item.PSObject.Properties.Name -contains 'FailedCount') {
        $failedCount = $item.FailedCount
      }

      $message = "[$($item.Index)] $($item.FileName) - $($item.Status)"
      if ($deletedCount -gt 0 -or $missingCount -gt 0 -or $failedCount -gt 0) {
        $message += " (Deleted: $deletedCount, Missing: $missingCount, Failed: $failedCount)"
      }
      if ($item.Status -eq 'Failed' -and $item.PSObject.Properties.Name -contains 'ErrorMessage') {
        $message += " Error: $($item.ErrorMessage)"
      }

      $level = switch ($item.Status) {
        'Failed' { 'ERROR' }  # Always show errors
        'PartiallyCleaned' { if ($script:VhdxCleanupShowDetails) { 'WARN' } else { 'DEBUG' } }
        'Skipped' { if ($script:VhdxCleanupShowDetails) { 'WARN' } else { 'DEBUG' } }
        default { if ($script:VhdxCleanupShowDetails) { 'INFO' } else { 'DEBUG' } }
      }

      Write-VhdxCleanupLog -Message $message -Level $level -LogFile $LogFile
    }
  }
}

function Get-VhdxImageList {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$TargetFolder
  )

  $images = Get-ChildItem -Path $TargetFolder -Recurse -File -Include *.vhd,*.vhdx |
    Sort-Object -Property FullName |
    ForEach-Object { $_.FullName }

  # Ensure we always return an array, even if empty
  if ($null -eq $images) {
    return @()
  }

  # If single item, wrap in array; otherwise return as-is
  if ($images -is [System.Array]) {
    return $images
  } else {
    return @($images)
  }
}

function Mount-VhdxImage {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$ImagePath
  )

  # Mount the disk image using Windows Storage API (same as Disk Management)
  $null = Mount-DiskImage -ImagePath $ImagePath -Access ReadWrite -ErrorAction Stop
  
  # Get the disk number from the mounted image
  # After mounting, get the disk image object to find the associated disk
  Start-Sleep -Milliseconds 500  # Brief pause to ensure disk is recognized
  $diskImage = Get-DiskImage -ImagePath $ImagePath -ErrorAction Stop
  
  if (-not $diskImage) {
    throw "Could not retrieve disk image information after mounting: $ImagePath"
  }
  
  # Find the disk associated with this image by checking all disks
  $disk = $null
  $allDisks = Get-Disk
  foreach ($d in $allDisks) {
    try {
      $img = Get-DiskImage -DevicePath $d.Path -ErrorAction SilentlyContinue
      if ($img -and $img.ImagePath -eq $ImagePath) {
        $disk = $d
        break
      }
    } catch {
      # Continue checking other disks
    }
  }
  
  if (-not $disk) {
    throw "Could not find disk for mounted image: $ImagePath"
  }
  
  $diskNumber = $disk.Number

  $partitions = $disk | Get-Partition -ErrorAction Stop

  if (-not $partitions) {
    throw "No partitions found for mounted image: $ImagePath"
  }

  $partitionWithLetter = $partitions | Where-Object { $_.DriveLetter } | Select-Object -First 1

  if (-not $partitionWithLetter) {
    $targetPartition = $partitions | Select-Object -First 1
    Add-PartitionAccessPath -DiskNumber $targetPartition.DiskNumber -PartitionNumber $targetPartition.PartitionNumber -AssignDriveLetter -ErrorAction Stop | Out-Null

    $partitionWithLetter = Get-Partition -DiskNumber $targetPartition.DiskNumber -PartitionNumber $targetPartition.PartitionNumber -ErrorAction Stop
  }

  if (-not $partitionWithLetter.DriveLetter) {
    throw "Mounted image has no drive letter after assignment: $ImagePath"
  }

  $driveLetter = $partitionWithLetter.DriveLetter
  $rootPath = "${driveLetter}:\"

  return [pscustomobject]@{
    ImagePath  = $ImagePath
    DiskNumber = $diskNumber
    DriveLetter = $driveLetter
    RootPath   = $rootPath
  }
}

function Invoke-VhdxPathCleanup {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$RootPath,

    [Parameter(Mandatory = $true)]
    [string[]]$DeletePaths
  )

  $results = New-Object System.Collections.Generic.List[object]
  $deletedCount = 0
  $missingCount = 0
  $failedCount = 0

  foreach ($relativePath in $DeletePaths) {
    $targetPath = Join-Path -Path $RootPath -ChildPath $relativePath
    $status = 'Unknown'
    $errorMessage = $null

    if (Test-Path -Path $targetPath) {
      try {
        Remove-Item -Path $targetPath -Recurse -Force -ErrorAction Stop
        $status = 'Deleted'
        $deletedCount++
      } catch {
        $status = 'Failed'
        $errorMessage = $_.Exception.Message
        $failedCount++
      }
    } else {
      $status = 'Missing'
      $missingCount++
    }

    $result = [pscustomobject]@{
      Path   = $targetPath
      Status = $status
    }
    
    if ($errorMessage) {
      $result | Add-Member -NotePropertyName ErrorMessage -NotePropertyValue $errorMessage -Force
    }
    
    $results.Add($result)
  }

  return [pscustomobject]@{
    DeletedCount = $deletedCount
    MissingCount = $missingCount
    FailedCount  = $failedCount
    PathResults  = $results.ToArray()
  }
}

function Invoke-VhdxCleanup {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$TargetFolder,

    [Parameter(Mandatory = $true)]
    [string[]]$DeletePath
  )

  $exitCodeMapping = Get-VhdxCleanupExitCodeMapping

  if (-not (Test-VhdxCleanupAdminPrivileges)) {
    $exitCodeInfo = $exitCodeMapping.InvalidInput
    Write-VhdxCleanupExitCode -ExitCodeInfo $exitCodeInfo -LogFile $null
    return $exitCodeInfo.Code
  }

  if (-not (Test-VhdxCleanupInputs -TargetFolder $TargetFolder -DeletePath $DeletePath)) {
    $exitCodeInfo = $exitCodeMapping.InvalidInput
    Write-VhdxCleanupExitCode -ExitCodeInfo $exitCodeInfo -LogFile $null
    return $exitCodeInfo.Code
  }

  if (-not (Test-VhdxCleanupStorageModule)) {
    $exitCodeInfo = $exitCodeMapping.InvalidInput
    Write-VhdxCleanupExitCode -ExitCodeInfo $exitCodeInfo -LogFile $null
    return $exitCodeInfo.Code
  }

  # Set log level based on Verbose parameter
  $isVerbose = $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose') -and $PSCmdlet.MyInvocation.BoundParameters['Verbose']
  if ($isVerbose) {
    $script:VhdxCleanupLogLevel = 'DEBUG'
    
    # Display verbose information banner
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  VHDX Cleanup - Verbose Mode Enabled  " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "System Information:" -ForegroundColor Yellow
    Write-Host "  Script Version    : 1.0" -ForegroundColor White
    Write-Host "  PowerShell Version : $($PSVersionTable.PSVersion)" -ForegroundColor White
    Write-Host "  Computer Name      : $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "  User               : $env:USERNAME" -ForegroundColor White
    Write-Host "  OS Version         : $([System.Environment]::OSVersion.VersionString)" -ForegroundColor White
    Write-Host "  Admin Privileges   : $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))" -ForegroundColor White
    Write-Host ""
    Write-Host "Configuration:" -ForegroundColor Yellow
    Write-Host "  Target Folder      : $TargetFolder" -ForegroundColor White
    Write-Host "  Log Level          : DEBUG" -ForegroundColor White
    Write-Host "  Log Rotation       : Last 10 files" -ForegroundColor White
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
  }
  
  # Set detailed output flag based on ShowDetails parameter
  $script:VhdxCleanupShowDetails = $ShowDetails.IsPresent
  
  # Adjust log level based on ShowDetails
  # When ShowDetails is on, show INFO and above; when off, only show ERROR
  if ($script:VhdxCleanupShowDetails) {
    $script:VhdxCleanupLogLevel = 'INFO'
  } else {
    $script:VhdxCleanupLogLevel = 'ERROR'
  }

  $script:VhdxCleanupStartTime = Get-Date
  $logFilePath = New-VhdxCleanupLog -TargetFolder $TargetFolder
  $script:VhdxCleanupLogFile = $logFilePath
  
  # Log startup info to file (always), but only show on console if ShowDetails is enabled
  Write-VhdxCleanupLog -Message "=== VHDX Cleanup Started ===" -Level DEBUG -LogFile $logFilePath
  Write-VhdxCleanupLog -Message "Script Version: 1.0" -Level DEBUG -LogFile $logFilePath
  Write-VhdxCleanupLog -Message "PowerShell Version: $($PSVersionTable.PSVersion)" -Level DEBUG -LogFile $logFilePath
  Write-VhdxCleanupLog -Message "Computer Name: $env:COMPUTERNAME" -Level DEBUG -LogFile $logFilePath
  Write-VhdxCleanupLog -Message "User: $env:USERNAME" -Level DEBUG -LogFile $logFilePath
  Write-VhdxCleanupLog -Message "OS Version: $([System.Environment]::OSVersion.VersionString)" -Level DEBUG -LogFile $logFilePath
  $startTimeStr = $script:VhdxCleanupStartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  Write-VhdxCleanupLog -Message "Start Time: $startTimeStr" -Level DEBUG -LogFile $logFilePath
  
  $normalizedDeletePaths = Normalize-DeletePaths -DeletePath $DeletePath
  $imageList = Get-VhdxImageList -TargetFolder $TargetFolder

  # Ensure imageList is always an array
  if ($null -eq $imageList) {
    $imageList = @()
  } elseif (-not ($imageList -is [System.Array])) {
    $imageList = @($imageList)
  }

  $workItems = @()
  if ($imageList.Count -gt 0) {
    $workItems = for ($index = 0; $index -lt $imageList.Count; $index++) {
      $imagePath = $imageList[$index]
      [pscustomobject]@{
        Index    = $index + 1
        Path     = $imagePath
        FileName = [System.IO.Path]::GetFileName($imagePath)
        Status   = 'Pending'
      }
    }
  }

  # Ensure workItems is always an array
  if ($null -eq $workItems) {
    $workItems = @()
  } elseif (-not ($workItems -is [System.Array])) {
    $workItems = @($workItems)
  }

  # Safely calculate pending count
  $pendingItems = @($workItems | Where-Object { $_.Status -eq 'Pending' })
  $pendingCount = if ($null -eq $pendingItems) { 0 } else { $pendingItems.Count }

  $summary = [pscustomobject]@{
    TargetFolder   = $TargetFolder
    DeletePaths    = $normalizedDeletePaths
    ImageCount     = if ($null -eq $imageList) { 0 } else { $imageList.Count }
    ImageList      = $imageList
    LogFile        = $logFilePath
    WorkItems      = $workItems
    WorkItemCount  = if ($null -eq $workItems) { 0 } else { $workItems.Count }
    PendingCount   = $pendingCount
  }

  # Show detailed operational information only if ShowDetails is enabled
  if ($script:VhdxCleanupShowDetails) {
    Write-VhdxCleanupLog -Message "=== VHDX Cleanup Started ===" -Level INFO -LogFile $logFilePath
    Write-VhdxCleanupLog -Message "Target folder: $($summary.TargetFolder)" -Level INFO -LogFile $logFilePath
    $deletePathsStr = $summary.DeletePaths -join ', '
    Write-VhdxCleanupLog -Message "Delete paths: $deletePathsStr" -Level INFO -LogFile $logFilePath
    Write-VhdxCleanupLog -Message "Discovered images: $($summary.ImageCount)" -Level INFO -LogFile $logFilePath
    Write-VhdxCleanupLog -Message "Work items: $($summary.WorkItemCount)" -Level INFO -LogFile $logFilePath
    Write-VhdxCleanupLog -Message "Pending work items: $($summary.PendingCount)" -Level INFO -LogFile $logFilePath
  } else {
    # Still log to file, but don't show on console
    Write-VhdxCleanupLog -Message "=== VHDX Cleanup Started ===" -Level DEBUG -LogFile $logFilePath
    Write-VhdxCleanupLog -Message "Target folder: $($summary.TargetFolder)" -Level DEBUG -LogFile $logFilePath
    $deletePathsStr = $summary.DeletePaths -join ', '
    Write-VhdxCleanupLog -Message "Delete paths: $deletePathsStr" -Level DEBUG -LogFile $logFilePath
    Write-VhdxCleanupLog -Message "Discovered images: $($summary.ImageCount)" -Level DEBUG -LogFile $logFilePath
    Write-VhdxCleanupLog -Message "Work items: $($summary.WorkItemCount)" -Level DEBUG -LogFile $logFilePath
    Write-VhdxCleanupLog -Message "Pending work items: $($summary.PendingCount)" -Level DEBUG -LogFile $logFilePath
  }
  
  # Display verbose information about discovered images
  if ($isVerbose -and $summary.ImageCount -gt 0) {
    Write-Host ""
    Write-Host "Discovered Images:" -ForegroundColor Yellow
    foreach ($imagePath in $summary.ImageList) {
      $imageName = [System.IO.Path]::GetFileName($imagePath)
      $imageSize = if (Test-Path $imagePath) {
        $size = (Get-Item $imagePath).Length
        if ($size -gt 1GB) {
          "{0:N2} GB" -f ($size / 1GB)
        } elseif ($size -gt 1MB) {
          "{0:N2} MB" -f ($size / 1MB)
        } else {
          "{0:N2} KB" -f ($size / 1KB)
        }
      } else {
        "Unknown"
      }
      Write-Host "  - $imageName ($imageSize)" -ForegroundColor White
    }
    Write-Host ""
  }

  if ($summary.WorkItemCount -gt 0) {
    if ($script:VhdxCleanupShowDetails) {
      Write-VhdxCleanupLog -Message "Work list:" -Level INFO -LogFile $logFilePath
      foreach ($item in $summary.WorkItems) {
        Write-VhdxCleanupLog -Message "[$($item.Index)] $($item.FileName) - $($item.Status)" -Level INFO -LogFile $logFilePath
      }
      Write-VhdxCleanupLog -Message "Cleaning images:" -Level INFO -LogFile $logFilePath
    } else {
      # Log to file only, don't show on console
      Write-VhdxCleanupLog -Message "Work list:" -Level DEBUG -LogFile $logFilePath
      foreach ($item in $summary.WorkItems) {
        Write-VhdxCleanupLog -Message "[$($item.Index)] $($item.FileName) - $($item.Status)" -Level DEBUG -LogFile $logFilePath
      }
      Write-VhdxCleanupLog -Message "Cleaning images:" -Level DEBUG -LogFile $logFilePath
    }
    $itemIndex = 0
    foreach ($item in $summary.WorkItems) {
      $itemIndex++
      $itemStartTime = Get-Date
      $mountInfo = $null
      $isMounted = $false

      Write-VhdxCleanupLog -Message "[$($item.Index)/$($summary.WorkItemCount)] Processing $($item.FileName)..." -Level DEBUG -LogFile $logFilePath

      try {
        $mountStartTime = Get-Date
        $mountInfo = Mount-VhdxImage -ImagePath $item.Path
        $isMounted = $true
        $mountDuration = (Get-Date) - $mountStartTime
        Write-VhdxCleanupLog -Message "  Mounted in $([math]::Round($mountDuration.TotalSeconds, 2))s" -Level DEBUG -LogFile $logFilePath

        $item | Add-Member -NotePropertyName DiskNumber -NotePropertyValue $mountInfo.DiskNumber -Force
        $item | Add-Member -NotePropertyName DriveLetter -NotePropertyValue $mountInfo.DriveLetter -Force
        $item | Add-Member -NotePropertyName RootPath -NotePropertyValue $mountInfo.RootPath -Force

        $cleanupResult = Invoke-VhdxPathCleanup -RootPath $mountInfo.RootPath -DeletePaths $normalizedDeletePaths

        $item | Add-Member -NotePropertyName DeletedCount -NotePropertyValue $cleanupResult.DeletedCount -Force
        $item | Add-Member -NotePropertyName MissingCount -NotePropertyValue $cleanupResult.MissingCount -Force
        $item | Add-Member -NotePropertyName FailedCount -NotePropertyValue $cleanupResult.FailedCount -Force
        $item | Add-Member -NotePropertyName PathResults -NotePropertyValue $cleanupResult.PathResults -Force
        
        # Log details for each path result (only show if ShowDetails is enabled)
        foreach ($pathResult in $cleanupResult.PathResults) {
          $pathLevel = switch ($pathResult.Status) {
            'Deleted' { if ($script:VhdxCleanupShowDetails) { 'INFO' } else { 'DEBUG' } }
            'Missing' { if ($script:VhdxCleanupShowDetails) { 'WARN' } else { 'DEBUG' } }
            'Failed' { 'ERROR' }  # Always show errors
            default { if ($script:VhdxCleanupShowDetails) { 'INFO' } else { 'DEBUG' } }
          }
          $pathMessage = "  Path: $($pathResult.Path) - $($pathResult.Status)"
          if ($pathResult.Status -eq 'Failed' -and $pathResult.PSObject.Properties.Name -contains 'ErrorMessage') {
            $pathMessage += " ($($pathResult.ErrorMessage))"
          }
          Write-VhdxCleanupLog -Message $pathMessage -Level $pathLevel -LogFile $logFilePath
        }
        
        # Determine overall status
        if ($cleanupResult.FailedCount -gt 0) {
          $item.Status = 'PartiallyCleaned'
        } else {
          $item.Status = 'Cleaned'
        }

        $itemDuration = (Get-Date) - $itemStartTime
        # Only show errors on console when ShowDetails is off; show everything when ShowDetails is on
        if ($cleanupResult.FailedCount -gt 0) {
          $cleanupLevel = 'ERROR'  # Always show errors
        } elseif ($script:VhdxCleanupShowDetails) {
          $cleanupLevel = if ($cleanupResult.MissingCount -gt 0) { 'WARN' } else { 'SUCCESS' }
        } else {
          $cleanupLevel = 'DEBUG'  # Hide success/warning messages when ShowDetails is off
        }
        $summaryMessage = "[$($item.Index)] Cleaned $($item.FileName) at $($mountInfo.RootPath) (Deleted: $($cleanupResult.DeletedCount), Missing: $($cleanupResult.MissingCount), Failed: $($cleanupResult.FailedCount)) - Duration: $([math]::Round($itemDuration.TotalSeconds, 2))s"
        Write-VhdxCleanupLog -Message $summaryMessage -Level $cleanupLevel -LogFile $logFilePath
      } catch {
        $errorMessage = $_.Exception.Message
        $item.Status = 'Failed'
        $item | Add-Member -NotePropertyName ErrorMessage -NotePropertyValue $errorMessage -Force
        Write-VhdxCleanupLog -Message "[$($item.Index)] Failed $($item.FileName): $errorMessage" -Level ERROR -LogFile $logFilePath
      } finally {
        if ($isMounted) {
          try {
            Dismount-DiskImage -ImagePath $item.Path -ErrorAction Stop
          } catch {
            $dismountMessage = $_.Exception.Message
            if (-not $item.PSObject.Properties.Match('ErrorMessage')) {
              $item | Add-Member -NotePropertyName ErrorMessage -NotePropertyValue $dismountMessage -Force
            }
            $item | Add-Member -NotePropertyName DismountError -NotePropertyValue $dismountMessage -Force
            $item.Status = 'Failed'
            Write-VhdxCleanupLog -Message "[$($item.Index)] Failed to dismount $($item.FileName): $dismountMessage" -Level ERROR -LogFile $logFilePath
          }
        }
      }
    }
  }

  # Safely calculate counts, ensuring we always have arrays
  $completedItems = @($summary.WorkItems | Where-Object { $_.Status -eq 'Cleaned' })
  $partiallyCleanedItems = @($summary.WorkItems | Where-Object { $_.Status -eq 'PartiallyCleaned' })
  $failedItems = @($summary.WorkItems | Where-Object { $_.Status -eq 'Failed' })
  $skippedItems = @($summary.WorkItems | Where-Object { $_.Status -eq 'Skipped' })

  $completedCount = if ($null -eq $completedItems) { 0 } else { $completedItems.Count }
  $partiallyCleanedCount = if ($null -eq $partiallyCleanedItems) { 0 } else { $partiallyCleanedItems.Count }
  $failedCount = if ($null -eq $failedItems) { 0 } else { $failedItems.Count }
  $skippedCount = if ($null -eq $skippedItems) { 0 } else { $skippedItems.Count }
  
  # Include partially cleaned in completed count for summary
  $totalCompletedCount = $completedCount + $partiallyCleanedCount

  $summary | Add-Member -NotePropertyName CompletedCount -NotePropertyValue $totalCompletedCount -Force
  $summary | Add-Member -NotePropertyName PartiallyCleanedCount -NotePropertyValue $partiallyCleanedCount -Force
  $summary | Add-Member -NotePropertyName FailedCount -NotePropertyValue $failedCount -Force
  $summary | Add-Member -NotePropertyName SkippedCount -NotePropertyValue $skippedCount -Force

  Write-VhdxCleanupSummary -Summary $summary -LogFile $logFilePath

  # Add performance summary (only show if ShowDetails is enabled)
  $totalDuration = (Get-Date) - $script:VhdxCleanupStartTime
  $perfLevel = if ($script:VhdxCleanupShowDetails) { 'INFO' } else { 'DEBUG' }
  Write-VhdxCleanupLog -Message "=== Performance Summary ===" -Level $perfLevel -LogFile $logFilePath
  Write-VhdxCleanupLog -Message "Total Duration: $([math]::Round($totalDuration.TotalSeconds, 2))s ($([math]::Round($totalDuration.TotalMinutes, 2)) minutes)" -Level $perfLevel -LogFile $logFilePath
  if ($summary.WorkItemCount -gt 0) {
    $avgTimePerItem = $totalDuration.TotalSeconds / $summary.WorkItemCount
    Write-VhdxCleanupLog -Message "Average Time per Image: $([math]::Round($avgTimePerItem, 2))s" -Level $perfLevel -LogFile $logFilePath
  }
  Write-VhdxCleanupLog -Message "End Time: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))" -Level DEBUG -LogFile $logFilePath
  Write-VhdxCleanupLog -Message "=== VHDX Cleanup Completed ===" -Level $perfLevel -LogFile $logFilePath

  # Determine exit outcome: consider both image-level failures and path-level failures
  $exitOutcome = if ($failedCount -gt 0) {
    # Some images completely failed
    if ($totalCompletedCount -gt 0) { 'PartialFailure' } else { 'RuntimeFailure' }
  } elseif ($partiallyCleanedCount -gt 0) {
    # Some images had path deletion failures
    'PartialFailure'
  } else {
    'Success'
  }

  $exitCodeInfo = $exitCodeMapping[$exitOutcome]
  Write-VhdxCleanupExitCode -ExitCodeInfo $exitCodeInfo -LogFile $logFilePath

  return $exitCodeInfo.Code
}

try {
  $exitCode = Invoke-VhdxCleanup -TargetFolder $TargetFolder -DeletePath $DeletePath
} catch {
  $exitCodeMapping = Get-VhdxCleanupExitCodeMapping
  $exitCodeInfo = $exitCodeMapping.FatalError
  $fatalMessage = $_.Exception.Message

  if ($script:VhdxCleanupLogFile) {
    Write-VhdxCleanupLog -Message "Fatal error: $fatalMessage" -Level ERROR -LogFile $script:VhdxCleanupLogFile
    Write-VhdxCleanupExitCode -ExitCodeInfo $exitCodeInfo -LogFile $script:VhdxCleanupLogFile
  } else {
    Write-Error "Fatal error: $fatalMessage"
    Write-VhdxCleanupExitCode -ExitCodeInfo $exitCodeInfo -LogFile $null
  }

  $exitCode = $exitCodeInfo.Code
}

exit $exitCode
