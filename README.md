# Windows Persistence Scanner

A Python-based Windows security auditing tool designed to identify common **persistence and autostart mechanisms** on Windows systems.

Windows Persistence Scanner enumerates startup locations, Registry entries, scheduled tasks, and Windows services, then analyzes discovered executables using file existence checks, publisher information, SHA-256 hashing, and security-focused heuristics.

The tool is **read-only** and does not disable, delete, or modify discovered persistence mechanisms.

---

## Features

- Scans the **Current User Startup folder**
- Scans the **All Users Startup folder**
- Enumerates `HKCU` Registry `Run` and `RunOnce` entries
- Enumerates `HKLM` Registry `Run` and `RunOnce` entries
- Checks both **32-bit and 64-bit Registry views**
- Enumerates **Windows Scheduled Tasks**
- Enumerates **Windows Services**
- Identifies whether an entry applies to the **Current User** or **System / All Users**
- Extracts executable paths from startup commands
- Resolves Windows `.lnk` shortcuts
- Checks whether referenced files exist
- Retrieves Authenticode publisher/signature information
- Calculates **SHA-256 hashes**
- Detects potentially suspicious startup characteristics
- Assigns **HIGH, MEDIUM, LOW, or CLEAN** review levels
- Displays color-coded results directly in the console
- Provides detailed information for flagged entries

---

## Screenshot

Add a screenshot of the scanner here:

```text
screenshots/
└── scanner-output.png
```

Example:

```markdown
![Windows Persistence Scanner](screenshots/scanner-output.png)
```

---

## Persistence Locations

The scanner currently examines the following Windows autostart and persistence mechanisms.

### Startup Folders

**Current User**

```text
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
```

**All Users**

```text
%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp
```

### Registry

Current-user startup entries:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run

HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

System-wide startup entries:

```text
HKLM\Software\Microsoft\Windows\CurrentVersion\Run

HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

Both 32-bit and 64-bit Registry views are examined where applicable.

### Scheduled Tasks

The scanner enumerates Windows Scheduled Tasks and collects information including:

- Task name
- Task path
- Executable
- Arguments
- User
- State
- Run level

### Windows Services

Windows services are examined for information including:

- Service name
- Display name
- Startup mode
- Current state
- Service account
- Executable path

---

## Security Analysis

For each discovered entry, Windows Persistence Scanner attempts to collect:

| Field | Description |
|---|---|
| **Name** | Name of the startup entry, task, or service |
| **Scope** | Current User or System / All Users |
| **Startup Type** | Persistence mechanism responsible for execution |
| **Command** | Full startup command |
| **Executable Path** | Extracted executable or script path |
| **Exists** | Whether the referenced file currently exists |
| **Publisher** | Authenticode signer/publisher information |
| **SHA-256** | SHA-256 cryptographic hash of the file |
| **Flags** | Security heuristics triggered by the entry |

---

## Risk Highlighting

Results are color-coded to make unusual entries easier to identify.

### HIGH — Red

High-priority indicators currently include:

```text
TEMP_PATH
DOWNLOADS_PATH
ENCODED_COMMAND
HIDDEN_WINDOW
```

Examples include an executable launching directly from a temporary directory or a PowerShell command using encoded arguments.

### MEDIUM — Yellow

Medium-priority indicators include:

```text
MISSING_FILE
NETWORK_PATH
INTERPRETER
SCRIPT
```

These entries may require additional investigation but are not necessarily malicious.

### LOW — Magenta

Lower-priority indicators include:

```text
APPDATA
LOCAL_APPDATA
UNSIGNED
```

These are relatively weak indicators on their own. Many legitimate applications install components in AppData or use unsigned executables.

### CLEAN — Green

Green means none of the scanner's currently implemented heuristics were triggered.

**CLEAN does not guarantee that an entry is safe.**

---

## Important Note About Flags

A flagged entry does **not** mean that malware has been detected.

The scanner uses security heuristics to identify entries that may deserve additional investigation.

For example:

```text
APPDATA
```

may be completely legitimate because many applications execute from a user's AppData directory.

However, a combination such as:

```text
Scheduled Task
        ↓
PowerShell
        ↓
Hidden Window
        ↓
Encoded Command
        ↓
Executable or script in %TEMP%
```

would warrant closer examination.

The tool is intended to assist with **triage and investigation**, not make an automated malware determination.

---

## Requirements

- Windows 10 or Windows 11
- Python 3
- Windows PowerShell
- Administrator privileges recommended

No third-party Python packages are currently required.

The scanner relies primarily on Python's standard library and built-in Windows functionality.

---

## Installation

Clone the repository:

```powershell
git clone <your-repository-url>
```

Enter the project directory:

```powershell
cd windows-persistence-scanner
```

No additional Python dependencies are required.

---

## Usage

Open **PowerShell** or **Command Prompt**.

For the most complete results, run the terminal as **Administrator**.

Run:

```powershell
python windows_persistence_scanner.py
```

If your system uses the Python launcher:

```powershell
py windows_persistence_scanner.py
```

The scanner will begin enumerating persistence and autostart locations.

Example:

```text
================================================================================
 WINDOWS PERSISTENCE / AUTOSTART SCANNER
================================================================================

[*] Scanning Current User Startup folder...
[*] Scanning All Users Startup folder...
[*] Scanning Registry Run/RunOnce...
[*] Scanning Scheduled Tasks...
[*] Scanning Windows Services...
[*] Analyzing signatures, paths and SHA-256 hashes...
```

---

## Example Result

```text
WINDOWS PERSISTENCE / AUTOSTART ANALYSIS
====================================================================================================

Name             Scope               Startup Type       Exists   Flags
----------------------------------------------------------------------------------------------------
SecurityHealth   All Users           Registry Run       YES      None
ExampleUpdater   Current User        Scheduled Task     YES      LOCAL_APPDATA
UpdateCheck      Current User        Scheduled Task     YES      ENCODED_COMMAND, HIDDEN_WINDOW
OldApplication   All Users           Registry Run       NO       MISSING_FILE
```

The actual console output contains additional columns and color-coded highlighting.

---

## SHA-256 Hashing

When a referenced executable exists, the scanner calculates its SHA-256 hash.

Example:

```text
SHA-256:
7a9c9e4b67f0d9c8c3e7a12f...
```

Hashes can assist security analysts with:

- File identification
- Incident response
- Threat hunting
- Malware investigation
- Comparing binaries between systems
- Searching threat-intelligence platforms

A hash alone does not determine whether a file is malicious.

---

## Publisher Verification

The scanner uses Windows Authenticode information to attempt to determine the publisher of discovered executables.

Possible results include:

```text
CN=Microsoft Windows, O=Microsoft Corporation...
```

```text
Unsigned
```

```text
Unknown
```

```text
N/A
```

An unsigned executable is **not automatically malicious**. Publisher information should be considered alongside the file location, startup mechanism, command line, hash, and other evidence.

---

## Current User vs. All Users

Where Windows exposes this distinction directly, the scanner identifies whether persistence applies to the current user or system-wide.

Examples:

```text
HKCU
→ Current User
```

```text
HKLM
→ All Users
```

```text
Current User Startup Folder
→ Current User
```

```text
Common Startup Folder
→ All Users
```

Scheduled tasks and Windows services do not always map cleanly to this distinction. System-level entries are therefore generally displayed as:

```text
System / All Users
```

---

## Read-Only Design

Windows Persistence Scanner is designed as an enumeration and analysis utility.

It does **not**:

- Delete Registry entries
- Delete scheduled tasks
- Disable services
- Terminate processes
- Remove files
- Quarantine files
- Modify startup configuration

Potentially suspicious entries should be investigated before making system changes.

---

## Limitations

Windows provides many mechanisms that can be used for legitimate autostart functionality or persistence.

The current version focuses on:

```text
Startup Folders
Registry Run / RunOnce
Scheduled Tasks
Windows Services
```

It does not currently provide comprehensive coverage of every possible Windows persistence mechanism.

Potential future areas include:

- Winlogon
- AppInit DLLs
- Image File Execution Options
- WMI event subscriptions
- Registry policy startup locations
- Explorer/Shell extensions
- Additional service persistence analysis
- Additional scheduled-task analysis
- Startup Approved Registry locations

---

## Future Improvements

Potential improvements include:

- Combination-based risk scoring
- Detection of suspicious service paths
- Scheduled-task trigger analysis
- Parent directory reputation checks
- Additional Windows persistence locations
- File creation/modification timestamps
- PE metadata analysis
- Microsoft signature validation
- Duplicate hash detection
- Interactive filtering
- Optional JSON/CSV reporting
- VirusTotal hash lookup integration
- MITRE ATT&CK technique mapping

---

## Example Investigation Workflow

When an unusual entry is discovered:

1. Review the persistence mechanism.
2. Examine the complete command line.
3. Verify the executable path.
4. Check whether the file exists.
5. Review its digital signature and publisher.
6. Record the SHA-256 hash.
7. Examine the file's location.
8. Research the executable and publisher.
9. Correlate the entry with other system activity.
10. Determine whether remediation is appropriate.

Avoid deleting an entry solely because the scanner highlighted it.

---

## Security Use

This project is intended for:

- Cybersecurity education
- Defensive security
- Blue-team exercises
- Threat hunting
- Incident-response training
- Windows security auditing
- Digital-forensics practice
- Authorized system administration

Only analyze systems you own or have authorization to examine.

---

## Project Structure

```text
windows-persistence-scanner/
│
├── windows_persistence_scanner.py
├── README.md
├── LICENSE
│
└── screenshots/
    └── scanner-output.png
```

---

## Disclaimer

Windows Persistence Scanner is provided for educational, administrative, and defensive security purposes.

Security flags generated by the tool are heuristic indicators and should not be interpreted as definitive evidence that software is malicious.

Always validate findings before modifying or removing system components.

---

## License

Add the license selected for the project here.

For an open-source project, the MIT License is one commonly used option.

---

## Author

Developed as a Python cybersecurity project focused on Windows persistence enumeration, security auditing, and defensive analysis.
