<#
.SYNOPSIS
    Migrates user profiles from FSLogix VHD(X) containers to a Citrix UPM store.

.DESCRIPTION
    This script automates the process of migrating user profiles. It mounts a user's FSLogix
    profile disk, copies its contents to a UPM-compatible folder structure, and sets the
    correct folder ownership.

    The script provides robust logging, generates a final CSV report, and offers flexible
    ways to specify which users to migrate.

.PARAMETER FSLogixStorePath
    The UNC path to the root folder containing the FSLogix profile VHD(X) files.

.PARAMETER UPMStorePath
    The UNC path to the destination root folder for the UPM profiles.

.PARAMETER SamAccountName
    One or more user logon names (sAMAccountName) to migrate.

.PARAMETER ADGroup
    The name of an Active Directory group. All members of this group will be migrated.

.PARAMETER CsvPath
    The path to a CSV file containing user information. The file must contain a header
    named 'SamAccountName'.

.EXAMPLE
    # Migrate two specific users
    Start-VHDMigration -FSLogixStorePath "\\server\Profiles" -UPMStorePath "\\server\UPM" -SamAccountName "user01", "user02"

.EXAMPLE
    # Migrate all users from an AD group
    Start-VHDMigration -FSLogixStorePath "\\server\Profiles" -UPMStorePath "\\server\UPM" -ADGroup "FSLogix-Migration-Users"

.EXAMPLE
    # Migrate all users listed in a CSV file
    Start-VHDMigration -FSLogixStorePath "\\server\Profiles" -UPMStorePath "\\server\UPM" -CsvPath "C:\temp\usertomigrate.csv"

.NOTES
    Author: Technigma AI
    Created: 2025-08-22
    Version: 1.0
#>
function Start-VHDMigration {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FSLogixStorePath,

        [Parameter(Mandatory = $true)]
        [string]$UPMStorePath,

        [Parameter(ParameterSetName = 'Identity', Mandatory = $true)]
        [string[]]$SamAccountName,

        [Parameter(ParameterSetName = 'ADGroup', Mandatory = $true)]
        [string]$ADGroup,

        [Parameter(ParameterSetName = 'CSV', Mandatory = $true)]
        [string]$CsvPath
    )

    # --- 1. SCRIPT SETUP ---
    $logDir = "C:\MigrationLogs"
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory | Out-Null
    }
    $logPath = Join-Path $logDir "MigrationLog-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
    Start-Transcript -Path $logPath

    $migrationReport = @()
    $usersToMigrate = @()

    # Helper function to find an available drive letter
    function Get-AvailableDriveLetter {
        $usedLetters = (Get-Volume).DriveLetter | Where-Object { $_ -ne $null }
        # ASCII 67 to 90 represents C to Z
        $allLetters = [char[]](67..90)
        return $allLetters | Where-Object { $usedLetters -notcontains $_ } | Select-Object -First 1
    }

    # --- 2. GATHER USERS BASED ON PARAMETER SET ---
    try {
        switch ($PSCmdlet.ParameterSetName) {
            'Identity' {
                $usersToMigrate = $SamAccountName
            }
            'ADGroup' {
                Write-Host "Getting users from AD Group: $ADGroup..."
                $usersToMigrate = (Get-ADGroupMember -Identity $ADGroup).SamAccountName
            }
            'CSV' {
                Write-Host "Getting users from CSV: $CsvPath..."
                if (-not (Test-Path $CsvPath)) { throw "CSV file not found at: $CsvPath" }
                $usersToMigrate = (Import-Csv -Path $CsvPath).SamAccountName
            }
        }
        Write-Host "Found $($usersToMigrate.Count) user(s) to process." -ForegroundColor Cyan
    }
    catch {
        Write-Error "Failed to gather users. Error: $($_.Exception.Message)"
        Stop-Transcript
        return
    }


    # --- 3. MIGRATION LOOP ---
    foreach ($user in $usersToMigrate) {
        Write-Host "----------------------------------------------------"
        Write-Host "Starting migration for user: $user" -ForegroundColor Green

        $fslogixVHDX = $null
        $assignedDriveLetter = $null # Use a different variable to track assigned letter
        $disk = $null
        $partition = $null
        $status = $null

        try {
            # Get user's SID
            $adUser = Get-ADUser -Identity $user -ErrorAction Stop
            $sid = $adUser.SID.Value

            # Build possible FSLogix folder names
            $fslogixFolder1 = Join-Path $FSLogixStorePath "${sid}_${user}"
            $fslogixFolder2 = Join-Path $FSLogixStorePath "${user}_${sid}"

            # Determine which path exists
            $fslogixFolder = if (Test-Path $fslogixFolder1) { $fslogixFolder1 }
                             elseif (Test-Path $fslogixFolder2) { $fslogixFolder2 }
                             else { throw "No FSLogix profile folder found for $user." }

            # Locate the VHD/VHDX file
            $fslogixVHDX = Get-ChildItem -Path $fslogixFolder -Filter "Profile*.vhd*" |
                           Where-Object { $_.Extension -in ".vhd", ".vhdx" } |
                           Select-Object -First 1
            if (-not $fslogixVHDX) { throw "No 'Profile' VHD/VHDX file found for $user in $fslogixFolder." }

            # --- Start Correction ---
            # Mount VHDX
            Write-Host "Mounting $($fslogixVHDX.FullName)..."
            Mount-DiskImage -ImagePath $fslogixVHDX.FullName -ErrorAction Stop
            
            # Explicitly get the disk and partition objects after mounting. This is more reliable.
            $disk = Get-DiskImage -ImagePath $fslogixVHDX.FullName | Get-Disk
            if (-not $disk) { throw "Could not retrieve disk object after mounting." }
            # --- End Correction ---
            
            $partition = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Type -ne 'Reserved' }

            # Assign drive letter if needed
            if (-not $partition.DriveLetter) {
                $assignedDriveLetter = Get-AvailableDriveLetter
                if (-not $assignedDriveLetter) { throw "No available drive letters found." }
                Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath "${assignedDriveLetter}:\" -ErrorAction Stop
                Write-Host "Assigned temporary drive letter $assignedDriveLetter`: to VHDX."
            } else {
                $assignedDriveLetter = $partition.DriveLetter
            }

            $sourceProfilePath = "${assignedDriveLetter}:\Profile"
            if (-not (Test-Path $sourceProfilePath)) { throw "No 'Profile' folder found inside VHDX for $user." }

            # Define destination path
            $destinationParentFolder = Join-Path $UPMStorePath $user
            $destinationProfilePath  = Join-Path $destinationParentFolder "UPM_Profile"

            if (-not (Test-Path $destinationParentFolder)) {
                New-Item -Path $destinationParentFolder -ItemType Directory -Force | Out-Null
            }

            # Copy profile data using Robocopy
            Write-Host "Copying data from '$sourceProfilePath' to '$destinationProfilePath'..."
            robocopy $sourceProfilePath $destinationProfilePath /MIR /E /COPYALL /XJ /R:2 /W:5 /NFL /NDL /NJH /NJS | Out-Null

            # Set folder ownership
            Write-Host "Setting folder ownership for $user on '$destinationParentFolder'..."
            $acl = Get-Acl -Path $destinationParentFolder
            $acl.SetOwner($adUser.SID)
            Set-Acl -Path $destinationParentFolder -AclObject $acl
            
            Write-Host "Migration completed successfully for ${user}." -ForegroundColor Green
            $status = [pscustomobject]@{ User = $user; Timestamp = Get-Date; Status = "Success"; Details = "Profile copied and ownership set." }

        } catch {
            Write-Error "An error occurred while migrating ${user}: $($_.Exception.Message)"
            $status = [pscustomobject]@{ User = $user; Timestamp = Get-Date; Status = "Failed"; Details = $_.Exception.Message }
        } finally {
            # Clean up: dismount VHDX
            if ($fslogixVHDX) {
                $mountedImage = Get-DiskImage -ImagePath $fslogixVHDX.FullName -ErrorAction SilentlyContinue
                if ($mountedImage -and $mountedImage.Attached) {
                    Write-Host "Dismounting VHDX for $user..."
                    Dismount-DiskImage -ImagePath $fslogixVHDX.FullName -ErrorAction SilentlyContinue
                }
            }
            Write-Host "Finished processing user: $user"
            if ($status) { $migrationReport += $status }
        }
    }

    # --- 4. FINAL REPORTING ---
    $reportPath = Join-Path $logDir "MigrationReport.csv"
    $migrationReport | Export-Csv -Path $reportPath -NoTypeInformation

    Write-Host "----------------------------------------------------" -ForegroundColor Yellow
    Write-Host "All users processed. See full log at: $logPath" -ForegroundColor Yellow
    Write-Host "A summary report has been saved to: $reportPath" -ForegroundColor Yellow

    Stop-Transcript
}