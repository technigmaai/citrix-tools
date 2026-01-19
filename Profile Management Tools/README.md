# Profile Management Tools

This folder contains PowerShell tools for managing user profiles in Citrix environments. These tools help automate common profile management tasks, migrations, and maintenance operations.

## Tools Overview

### 1. FSLogix to File-Based UPM Migration Tool

**Script:** `FSLogix_to_file_based_UPM.ps1`  
**Function:** `Start-VHDMigration`

Migrates user profiles from FSLogix VHD(X) containers to a Citrix User Profile Management (UPM) file-based store. This tool automates the entire migration process, including mounting VHDX files, copying profile data, and setting proper folder ownership.

#### Features

- **Flexible User Selection**: Migrate users via:
  - Individual user accounts (sAMAccountName)
  - Active Directory groups
  - CSV file input
- **Robust Error Handling**: Each user migration is processed independently with comprehensive error handling
- **Automatic Cleanup**: VHDX files are automatically dismounted after processing
- **Comprehensive Logging**: Full transcript logging with timestamped log files
- **Migration Reports**: CSV report generated with success/failure status for each user
- **Drive Letter Management**: Automatically assigns available drive letters for VHDX mounting

#### Prerequisites

- **PowerShell 5.1 or later**
- **Active Directory PowerShell Module** (`RSAT-AD-PowerShell` or `ActiveDirectory` module)
- **Administrative Privileges** (required to mount VHDX files)
- **Network Access** to:
  - FSLogix profile store (UNC path)
  - UPM destination store (UNC path)
  - Active Directory domain controller
- **Robocopy** (included with Windows)

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `FSLogixStorePath` | String | Yes | UNC path to the root folder containing FSLogix profile VHD(X) files |
| `UPMStorePath` | String | Yes | UNC path to the destination root folder for UPM profiles |
| `SamAccountName` | String[] | Conditional* | One or more user logon names (sAMAccountName) to migrate |
| `ADGroup` | String | Conditional* | Name of an Active Directory group containing users to migrate |
| `CsvPath` | String | Conditional* | Path to a CSV file with a 'SamAccountName' column |

\* One of `SamAccountName`, `ADGroup`, or `CsvPath` must be provided.

#### Usage Examples

**Migrate specific users:**
```powershell
. .\FSLogix_to_file_based_UPM.ps1
Start-VHDMigration -FSLogixStorePath "\\server\Profiles" -UPMStorePath "\\server\UPM" -SamAccountName "user01", "user02"
```

**Migrate all users from an AD group:**
```powershell
. .\FSLogix_to_file_based_UPM.ps1
Start-VHDMigration -FSLogixStorePath "\\server\Profiles" -UPMStorePath "\\server\UPM" -ADGroup "FSLogix-Migration-Users"
```

**Migrate users from a CSV file:**
```powershell
. .\FSLogix_to_file_based_UPM.ps1
Start-VHDMigration -FSLogixStorePath "\\server\Profiles" -UPMStorePath "\\server\UPM" -CsvPath "C:\temp\usertomigrate.csv"
```

**CSV File Format:**
The CSV file must contain a header row with a column named `SamAccountName`:
```csv
SamAccountName
user01
user02
user03
```

#### How It Works

1. **User Discovery**: Based on the parameter set, the script gathers the list of users to migrate
2. **Profile Location**: For each user:
   - Retrieves the user's SID from Active Directory
   - Searches for FSLogix profile folders using common naming patterns (`{SID}_{User}` or `{User}_{SID}`)
   - Locates the Profile VHD/VHDX file within the folder
3. **VHDX Mounting**: 
   - Mounts the VHDX file using `Mount-DiskImage`
   - Retrieves the disk and partition information
   - Assigns a drive letter if one is not already assigned
4. **Data Migration**:
   - Uses Robocopy with `/MIR /E /COPYALL` flags to mirror the profile data
   - Copies from `{DriveLetter}:\Profile` to `{UPMStorePath}\{User}\UPM_Profile`
5. **Ownership Configuration**:
   - Sets the folder ownership to the user's SID
6. **Cleanup**:
   - Dismounts the VHDX file
   - Records the migration status
7. **Reporting**:
   - Generates a CSV report with migration results
   - Saves detailed transcript logs

#### Output Files

- **Log Files**: `C:\MigrationLogs\MigrationLog-{yyyy-MM-dd_HH-mm-ss}.txt`
  - Full transcript of the migration process
  - Includes all console output and errors
  
- **Migration Report**: `C:\MigrationLogs\MigrationReport.csv`
  - CSV file with columns: `User`, `Timestamp`, `Status`, `Details`
  - Status values: "Success" or "Failed"

#### Robocopy Flags Used

- `/MIR` - Mirror mode (synchronizes source and destination)
- `/E` - Copy subdirectories, including empty ones
- `/COPYALL` - Copy all file information (attributes, timestamps, security, owner, auditing)
- `/XJ` - Exclude junction points
- `/R:2` - Retry failed copies 2 times
- `/W:5` - Wait 5 seconds between retries
- `/NFL /NDL /NJH /NJS` - Suppress file, directory, header, and summary logging (output handled by transcript)

#### Error Handling

- Each user migration is wrapped in a try-catch-finally block
- Failures for one user do not stop processing of other users
- VHDX files are always dismounted in the finally block, even on errors
- All errors are logged to both the transcript and the migration report

#### Notes

- The script supports both `.vhd` and `.vhdx` file formats
- The script looks for VHDX files matching the pattern `Profile*.vhd*`
- Profile folders are created automatically if they don't exist
- The script requires at least one available drive letter (C-Z) for mounting VHDX files
- Uses `SupportsShouldProcess`, so you can use `-WhatIf` to preview actions

#### Version Information

- **Version**: 1.0
- **Author**: Technigma AI
- **Created**: 2025-08-22

---

## Future Tools

Additional profile management tools will be added to this folder as they are developed.

## License

This project is licensed under the MIT License. See the [LICENSE](../LICENSE) file for details.

**MIT License Conditions:**
- You are free to use, modify, distribute, and sell this software
- The software is provided "AS IS" without warranty
- You must include the original copyright notice and license text in any copies or substantial portions of the software
