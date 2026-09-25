import os
import re
import json
import hashlib
import subprocess
import winreg
from pathlib import Path


# ============================================================
# Windows Persistence / Autostart Scanner
#
# Enumerates:
#   - Current User Startup Folder
#   - All Users Startup Folder
#   - HKCU Run / RunOnce
#   - HKLM Run / RunOnce (32-bit + 64-bit)
#   - Windows Scheduled Tasks
#   - Windows Services
#
# Displays:
#   Name
#   Scope
#   Startup Type
#   Command
#   Executable Path
#   Exists
#   Publisher
#   SHA-256
#   Flags
#
# READ-ONLY: This script does not disable/delete/modify entries.
# ============================================================


results = []


# ============================================================
# CONSOLE COLORS
# ============================================================

RESET = "\033[0m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"


def enable_windows_ansi():
    """
    Enable ANSI escape processing on supported Windows consoles.
    Modern Windows Terminal / PowerShell generally supports this.
    """

    if os.name != "nt":
        return

    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32

        handle = kernel32.GetStdHandle(-11)

        mode = ctypes.c_uint32()

        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(
                handle,
                mode.value | 0x0004
            )

    except Exception:
        pass


# ============================================================
# GENERAL HELPERS
# ============================================================

def expand_path(value):

    if not value:
        return ""

    return os.path.expandvars(
        str(value).strip()
    )


def shorten(value, length):

    value = str(value)

    if len(value) <= length:
        return value

    return value[:length - 3] + "..."


def powershell(command, timeout=30):
    """
    Execute a PowerShell command and return stdout.
    """

    try:

        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        return result.stdout.strip()

    except Exception:
        return ""


# ============================================================
# EXECUTABLE PATH EXTRACTION
# ============================================================

def extract_executable(command):
    """
    Best-effort extraction of an executable/script path from a
    Windows command line.
    """

    if not command:
        return ""

    command = expand_path(command.strip())

    # Remove leading whitespace
    command = command.lstrip()

    # Quoted executable
    match = re.match(
        r'^"([^"]+\.(?:exe|com|bat|cmd|ps1|vbs|js|jse|wsf|scr|dll))"',
        command,
        re.I
    )

    if match:
        return match.group(1)

    # Unquoted executable
    match = re.match(
        r'^(.+?\.(?:exe|com|bat|cmd|ps1|vbs|js|jse|wsf|scr|dll))(?=\s|$)',
        command,
        re.I
    )

    if match:
        return match.group(1).strip()

    return command


# ============================================================
# SHORTCUT RESOLUTION
# ============================================================

def resolve_shortcut(shortcut):

    try:

        escaped = str(shortcut).replace(
            "'",
            "''"
        )

        command = (
            "$ws = New-Object -ComObject WScript.Shell;"
            f"$s = $ws.CreateShortcut('{escaped}');"
            "$s.TargetPath"
        )

        return expand_path(
            powershell(command, 10)
        )

    except Exception:
        return ""


# ============================================================
# SHA-256
# ============================================================

def calculate_sha256(file_path):

    if not file_path:
        return "N/A"

    if not os.path.isfile(file_path):
        return "N/A"

    try:

        sha = hashlib.sha256()

        with open(file_path, "rb") as file:

            while True:

                chunk = file.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                sha.update(chunk)

        return sha.hexdigest()

    except (PermissionError, OSError):
        return "ERROR"


# ============================================================
# AUTHENTICODE / PUBLISHER
# ============================================================

def get_publisher(file_path):

    if not file_path:
        return "N/A"

    if not os.path.isfile(file_path):
        return "N/A"

    try:

        escaped = file_path.replace(
            "'",
            "''"
        )

        command = (
            f"$sig = Get-AuthenticodeSignature "
            f"-LiteralPath '{escaped}';"
            "if ($sig.SignerCertificate) {"
            "$sig.SignerCertificate.Subject"
            "} elseif ($sig.Status -eq 'NotSigned') {"
            "'Unsigned'"
            "} else {"
            "'Unknown'"
            "}"
        )

        output = powershell(
            command,
            15
        )

        if output:
            return output

    except Exception:
        pass

    return "Unknown"


# ============================================================
# SECURITY HEURISTICS
# ============================================================

def suspicious_flags(
    executable_path,
    exists,
    publisher,
    command="",
    startup_type=""
):

    flags = []

    path = (
        executable_path or ""
    ).lower()

    command_lower = (
        command or ""
    ).lower()

    # --------------------------------------------------------
    # Missing executable
    # --------------------------------------------------------

    if executable_path and not exists:
        flags.append("MISSING_FILE")

    # --------------------------------------------------------
    # TEMP
    # --------------------------------------------------------

    temp_paths = [
        os.environ.get("TEMP", ""),
        os.environ.get("TMP", "")
    ]

    for temp in temp_paths:

        if (
            temp
            and path.startswith(
                temp.lower()
            )
        ):

            flags.append("TEMP_PATH")
            break

    # --------------------------------------------------------
    # Downloads
    # --------------------------------------------------------

    profile = os.environ.get(
        "USERPROFILE",
        ""
    )

    if profile:

        downloads = os.path.join(
            profile,
            "Downloads"
        ).lower()

        if path.startswith(downloads):
            flags.append("DOWNLOADS_PATH")

    # --------------------------------------------------------
    # AppData
    # --------------------------------------------------------

    roaming = os.environ.get(
        "APPDATA",
        ""
    ).lower()

    local = os.environ.get(
        "LOCALAPPDATA",
        ""
    ).lower()

    if roaming and path.startswith(roaming):
        flags.append("APPDATA")

    elif local and path.startswith(local):
        flags.append("LOCAL_APPDATA")

    # --------------------------------------------------------
    # Script execution
    # --------------------------------------------------------

    script_extensions = (
        ".ps1",
        ".vbs",
        ".js",
        ".jse",
        ".wsf",
        ".cmd",
        ".bat"
    )

    if path.endswith(script_extensions):
        flags.append("SCRIPT")

    # --------------------------------------------------------
    # Common script / LOLBin interpreters
    # --------------------------------------------------------

    interpreters = [
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe"
    ]

    for interpreter in interpreters:

        if interpreter in command_lower:

            flags.append(
                "INTERPRETER"
            )

            break

    # --------------------------------------------------------
    # Encoded PowerShell
    # --------------------------------------------------------

    encoded_patterns = [
        "-enc ",
        "-encodedcommand",
        "/encodedcommand"
    ]

    if any(
        pattern in command_lower
        for pattern in encoded_patterns
    ):
        flags.append("ENCODED_COMMAND")

    # --------------------------------------------------------
    # Hidden PowerShell
    # --------------------------------------------------------

    if (
        "powershell" in command_lower
        and (
            "-windowstyle hidden" in command_lower
            or "-w hidden" in command_lower
        )
    ):

        flags.append("HIDDEN_WINDOW")

    # --------------------------------------------------------
    # Network paths
    # --------------------------------------------------------

    if path.startswith("\\\\"):
        flags.append("NETWORK_PATH")

    # --------------------------------------------------------
    # Unsigned
    # --------------------------------------------------------

    if publisher == "Unsigned":
        flags.append("UNSIGNED")

    # Remove duplicates
    return list(dict.fromkeys(flags))


# ============================================================
# RESULT PROCESSING
# ============================================================

def add_result(
    name,
    scope,
    startup_type,
    command,
    executable_path
):

    executable_path = expand_path(
        executable_path
    )

    exists = bool(
        executable_path
        and os.path.isfile(
            executable_path
        )
    )

    publisher = get_publisher(
        executable_path
    )

    sha256 = calculate_sha256(
        executable_path
    )

    flags = suspicious_flags(
        executable_path,
        exists,
        publisher,
        command,
        startup_type
    )

    results.append(
        {
            "Name": str(name),
            "Scope": str(scope),
            "Startup Type": str(startup_type),
            "Command": str(command),
            "Executable Path": executable_path,
            "Exists": (
                "YES"
                if exists
                else "NO"
            ),
            "Publisher": publisher,
            "SHA-256": sha256,
            "Flags": (
                ", ".join(flags)
                if flags
                else "None"
            )
        }
    )


# ============================================================
# STARTUP FOLDERS
# ============================================================

def scan_startup_folder(
    folder_path,
    scope
):

    path = Path(folder_path)

    if not path.exists():
        return

    try:

        for entry in path.iterdir():

            command = str(entry)
            executable = str(entry)

            if entry.suffix.lower() == ".lnk":

                resolved = resolve_shortcut(
                    entry
                )

                if resolved:
                    executable = resolved

            add_result(
                entry.stem,
                scope,
                "Startup Folder",
                command,
                executable
            )

    except PermissionError:

        print(
            YELLOW
            + f"[!] Permission denied: {folder_path}"
            + RESET
        )


# ============================================================
# REGISTRY RUN / RUNONCE
# ============================================================

def scan_registry_key(
    hive,
    key_path,
    scope,
    startup_type,
    access_flags=0
):

    try:

        with winreg.OpenKey(
            hive,
            key_path,
            0,
            winreg.KEY_READ | access_flags
        ) as key:

            index = 0

            while True:

                try:

                    name, command, _ = (
                        winreg.EnumValue(
                            key,
                            index
                        )
                    )

                    command = str(command)

                    add_result(
                        name,
                        scope,
                        startup_type,
                        command,
                        extract_executable(
                            command
                        )
                    )

                    index += 1

                except OSError:
                    break

    except FileNotFoundError:
        pass

    except PermissionError:
        pass


def scan_registry():

    user_keys = [
        (
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "Registry Run"
        ),
        (
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "Registry RunOnce"
        )
    ]

    machine_keys = [
        (
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "Registry Run"
        ),
        (
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "Registry RunOnce"
        )
    ]

    # Current user
    for path, startup_type in user_keys:

        scan_registry_key(
            winreg.HKEY_CURRENT_USER,
            path,
            "Current User",
            startup_type
        )

    # 64-bit machine
    for path, startup_type in machine_keys:

        scan_registry_key(
            winreg.HKEY_LOCAL_MACHINE,
            path,
            "All Users",
            startup_type + " (64-bit)",
            winreg.KEY_WOW64_64KEY
        )

    # 32-bit machine
    for path, startup_type in machine_keys:

        scan_registry_key(
            winreg.HKEY_LOCAL_MACHINE,
            path,
            "All Users",
            startup_type + " (32-bit)",
            winreg.KEY_WOW64_32KEY
        )


# ============================================================
# WINDOWS SERVICES
# ============================================================

def scan_services():

    command = r"""
Get-CimInstance Win32_Service |
Where-Object {
    $_.StartMode -eq 'Auto' -or
    $_.StartMode -eq 'Manual'
} |
Select-Object Name, DisplayName, StartMode, State, StartName, PathName |
ConvertTo-Json -Compress
"""

    output = powershell(
        command,
        60
    )

    if not output:
        return

    try:

        services = json.loads(
            output
        )

    except json.JSONDecodeError:
        return

    if isinstance(services, dict):
        services = [services]

    for service in services:

        path_name = (
            service.get("PathName")
            or ""
        )

        executable = extract_executable(
            path_name
        )

        service_name = (
            service.get("Name")
            or "Unknown"
        )

        display_name = (
            service.get("DisplayName")
            or service_name
        )

        start_mode = (
            service.get("StartMode")
            or "Unknown"
        )

        state = (
            service.get("State")
            or "Unknown"
        )

        account = (
            service.get("StartName")
            or "Unknown"
        )

        name = (
            f"{display_name} "
            f"[{service_name}]"
        )

        startup_type = (
            f"Service ({start_mode})"
        )

        scope = (
            f"System / All Users"
        )

        command_display = (
            f"{path_name} "
            f"[State={state}; "
            f"Account={account}]"
        )

        add_result(
            name,
            scope,
            startup_type,
            command_display,
            executable
        )


# ============================================================
# SCHEDULED TASKS
# ============================================================

def scan_scheduled_tasks():

    command = r"""
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue

$result = foreach ($task in $tasks) {

    foreach ($action in $task.Actions) {

        [PSCustomObject]@{
            TaskName  = $task.TaskName
            TaskPath  = $task.TaskPath
            State     = [string]$task.State
            UserId    = [string]$task.Principal.UserId
            RunLevel  = [string]$task.Principal.RunLevel
            Execute   = [string]$action.Execute
            Arguments = [string]$action.Arguments
        }
    }
}

$result | ConvertTo-Json -Compress
"""

    output = powershell(
        command,
        60
    )

    if not output:
        return

    try:

        tasks = json.loads(
            output
        )

    except json.JSONDecodeError:
        return

    if isinstance(tasks, dict):
        tasks = [tasks]

    current_user = os.environ.get(
        "USERNAME",
        ""
    ).lower()

    for task in tasks:

        execute = (
            task.get("Execute")
            or ""
        )

        arguments = (
            task.get("Arguments")
            or ""
        )

        user_id = (
            task.get("UserId")
            or ""
        )

        command_line = (
            f'"{execute}" {arguments}'
        ).strip()

        task_name = (
            task.get("TaskName")
            or "Unknown"
        )

        task_path = (
            task.get("TaskPath")
            or "\\"
        )

        state = (
            task.get("State")
            or "Unknown"
        )

        run_level = (
            task.get("RunLevel")
            or "Unknown"
        )

        # Scheduled tasks aren't always cleanly
        # Current User vs All Users, but identify
        # obvious current-user ownership.

        if (
            current_user
            and current_user
            in user_id.lower()
        ):

            scope = "Current User"

        else:

            scope = "System / All Users"

        name = (
            f"{task_path}{task_name}"
        )

        command_display = (
            f"{command_line} "
            f"[User={user_id}; "
            f"State={state}; "
            f"RunLevel={run_level}]"
        )

        add_result(
            name,
            scope,
            "Scheduled Task",
            command_display,
            expand_path(execute)
        )


# ============================================================
# FLAG SEVERITY
# ============================================================

HIGH_FLAGS = {
    "TEMP_PATH",
    "DOWNLOADS_PATH",
    "ENCODED_COMMAND",
    "HIDDEN_WINDOW"
}

MEDIUM_FLAGS = {
    "MISSING_FILE",
    "NETWORK_PATH",
    "INTERPRETER",
    "SCRIPT"
}

LOW_FLAGS = {
    "APPDATA",
    "LOCAL_APPDATA",
    "UNSIGNED"
}


def get_severity(flags_string):

    if flags_string == "None":
        return "CLEAN"

    flags = {
        flag.strip()
        for flag in flags_string.split(",")
    }

    if flags & HIGH_FLAGS:
        return "HIGH"

    if flags & MEDIUM_FLAGS:
        return "MEDIUM"

    return "LOW"


def severity_color(severity):

    if severity == "HIGH":
        return RED

    if severity == "MEDIUM":
        return YELLOW

    if severity == "LOW":
        return MAGENTA

    return GREEN


# ============================================================
# CONSOLE TABLE
# ============================================================

def print_table():

    if not results:

        print(
            "\nNo autostart entries found."
        )

        return

    print("\n")

    print(
        BOLD
        + CYAN
        + "=" * 190
        + RESET
    )

    print(
        BOLD
        + CYAN
        + "WINDOWS PERSISTENCE / AUTOSTART ANALYSIS"
        + RESET
    )

    print(
        BOLD
        + CYAN
        + "=" * 190
        + RESET
    )

    headers = [
        ("Name", 27),
        ("Scope", 20),
        ("Startup Type", 25),
        ("Executable Path", 43),
        ("Exists", 7),
        ("Publisher", 27),
        ("SHA-256", 15),
        ("Flags", 30)
    ]

    header_line = ""

    for header, width in headers:

        header_line += (
            f"{header:<{width}} "
        )

    print(
        BOLD
        + header_line
        + RESET
    )

    print("-" * 190)

    for item in results:

        severity = get_severity(
            item["Flags"]
        )

        color = severity_color(
            severity
        )

        line = ""

        for header, width in headers:

            value = shorten(
                item[header],
                width
            )

            line += (
                f"{value:<{width}} "
            )

        print(
            color
            + line
            + RESET
        )

    print("=" * 190)


# ============================================================
# FLAGGED DETAILS
# ============================================================

def print_flagged_details():

    flagged = [
        item
        for item in results
        if item["Flags"] != "None"
    ]

    if not flagged:
        return

    print(
        "\n\n"
        + BOLD
        + "FLAGGED ENTRY DETAILS"
        + RESET
    )

    print("=" * 90)

    flagged.sort(
        key=lambda item: {
            "HIGH": 0,
            "MEDIUM": 1,
            "LOW": 2
        }.get(
            get_severity(
                item["Flags"]
            ),
            3
        )
    )

    for number, item in enumerate(
        flagged,
        start=1
    ):

        severity = get_severity(
            item["Flags"]
        )

        color = severity_color(
            severity
        )

        print(
            f"\n{color}"
            f"[{number}] "
            f"{severity}: "
            f"{item['Name']}"
            f"{RESET}"
        )

        print("-" * 90)

        print(
            f"Scope           : "
            f"{item['Scope']}"
        )

        print(
            f"Startup Type    : "
            f"{item['Startup Type']}"
        )

        print(
            f"Command         : "
            f"{item['Command']}"
        )

        print(
            f"Executable Path : "
            f"{item['Executable Path']}"
        )

        print(
            f"Exists          : "
            f"{item['Exists']}"
        )

        print(
            f"Publisher       : "
            f"{item['Publisher']}"
        )

        print(
            f"SHA-256         : "
            f"{item['SHA-256']}"
        )

        print(
            f"Flags           : "
            f"{color}"
            f"{item['Flags']}"
            f"{RESET}"
        )


# ============================================================
# SUMMARY
# ============================================================

def print_summary():

    high = 0
    medium = 0
    low = 0
    clean = 0

    for item in results:

        severity = get_severity(
            item["Flags"]
        )

        if severity == "HIGH":
            high += 1

        elif severity == "MEDIUM":
            medium += 1

        elif severity == "LOW":
            low += 1

        else:
            clean += 1

    print(
        "\n\n"
        + BOLD
        + CYAN
        + "SCAN SUMMARY"
        + RESET
    )

    print("=" * 60)

    print(
        f"Total entries      : "
        f"{len(results)}"
    )

    print(
        RED
        + f"High priority      : {high}"
        + RESET
    )

    print(
        YELLOW
        + f"Medium priority    : {medium}"
        + RESET
    )

    print(
        MAGENTA
        + f"Low priority       : {low}"
        + RESET
    )

    print(
        GREEN
        + f"No heuristic flags : {clean}"
        + RESET
    )

    print()

    print(
        RED
        + "HIGH"
        + RESET
        + "   = Stronger review indicators"
    )

    print(
        YELLOW
        + "MEDIUM"
        + RESET
        + " = Requires investigation"
    )

    print(
        MAGENTA
        + "LOW"
        + RESET
        + "    = Weak indicator / often legitimate"
    )

    print(
        GREEN
        + "GREEN"
        + RESET
        + "  = No current heuristic triggered"
    )

    print(
        "\nA flag does NOT mean that an entry is malicious."
    )


# ============================================================
# MAIN
# ============================================================

def main():

    enable_windows_ansi()

    print(
        BOLD
        + CYAN
        + "=" * 80
        + RESET
    )

    print(
        BOLD
        + CYAN
        + " WINDOWS PERSISTENCE / AUTOSTART SCANNER"
        + RESET
    )

    print(
        BOLD
        + CYAN
        + "=" * 80
        + RESET
    )

    # --------------------------------------------------------
    # Startup folders
    # --------------------------------------------------------

    print(
        "\n[*] Scanning Current User Startup folder..."
    )

    appdata = os.environ.get(
        "APPDATA"
    )

    if appdata:

        scan_startup_folder(
            os.path.join(
                appdata,
                "Microsoft",
                "Windows",
                "Start Menu",
                "Programs",
                "Startup"
            ),
            "Current User"
        )

    print(
        "[*] Scanning All Users Startup folder..."
    )

    programdata = os.environ.get(
        "PROGRAMDATA"
    )

    if programdata:

        scan_startup_folder(
            os.path.join(
                programdata,
                "Microsoft",
                "Windows",
                "Start Menu",
                "Programs",
                "StartUp"
            ),
            "All Users"
        )

    # --------------------------------------------------------
    # Registry
    # --------------------------------------------------------

    print(
        "[*] Scanning Registry Run/RunOnce..."
    )

    scan_registry()

    # --------------------------------------------------------
    # Scheduled tasks
    # --------------------------------------------------------

    print(
        "[*] Scanning Scheduled Tasks..."
    )

    scan_scheduled_tasks()

    # --------------------------------------------------------
    # Services
    # --------------------------------------------------------

    print(
        "[*] Scanning Windows Services..."
    )

    scan_services()

    # --------------------------------------------------------
    # Sort
    # --------------------------------------------------------

    print(
        "[*] Analyzing signatures, paths and SHA-256 hashes..."
    )

    results.sort(
        key=lambda item: (
            {
                "HIGH": 0,
                "MEDIUM": 1,
                "LOW": 2,
                "CLEAN": 3
            }.get(
                get_severity(
                    item["Flags"]
                ),
                4
            ),
            item["Startup Type"],
            item["Name"].lower()
        )
    )

    # --------------------------------------------------------
    # Results
    # --------------------------------------------------------

    print_table()

    print_summary()

    print_flagged_details()


if __name__ == "__main__":
    main()
