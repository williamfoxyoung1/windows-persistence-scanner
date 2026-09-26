import os
import re
import json
import shutil
import hashlib
import subprocess
import winreg
from pathlib import Path


# ============================================================
# WINDOWS PERSISTENCE SCANNER
# Conservative Risk-Scoring Edition
# ============================================================
#
# Scans:
#   - Current User Startup Folder
#   - All Users Startup Folder
#   - HKCU Run / RunOnce
#   - HKLM Run / RunOnce (32-bit + 64-bit)
#   - Scheduled Tasks
#   - Automatic Windows Services
#
# Collects:
#   - Name
#   - Scope
#   - Startup Type
#   - Command
#   - Launcher
#   - Target / payload when confidently identifiable
#   - File existence
#   - Publisher
#   - Authenticode status
#   - SHA-256
#   - Flags
#   - Risk score
#   - Severity
#
# IMPORTANT:
# This is a triage tool.
# A flag does NOT mean malware.
#
# No persistence entries are modified or deleted.
# ============================================================


results = []

HASH_CACHE = {}
SIGNATURE_CACHE = {}


# ============================================================
# COLORS
# ============================================================

RESET = "\033[0m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"
BOLD = "\033[1m"
DIM = "\033[2m"


def enable_windows_ansi():

    if os.name != "nt":
        return

    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)

        mode = ctypes.c_uint32()

        if kernel32.GetConsoleMode(
            handle,
            ctypes.byref(mode)
        ):
            kernel32.SetConsoleMode(
                handle,
                mode.value | 0x0004
            )

    except Exception:
        pass


# ============================================================
# POWERSHELL
# ============================================================

def powershell(command, timeout=30):

    try:

        creation_flags = 0

        if os.name == "nt":
            creation_flags = subprocess.CREATE_NO_WINDOW

        process = subprocess.run(
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
            creationflags=creation_flags
        )

        return process.stdout.strip()

    except Exception:
        return ""


# ============================================================
# ENVIRONMENT / PATH HELPERS
# ============================================================

def expand_environment_variables(value):

    if not value:
        return ""

    value = str(value)

    value = os.path.expandvars(value)

    system_root = os.environ.get(
        "SystemRoot",
        r"C:\Windows"
    )

    replacements = {
        "%windir%": system_root,
        "%systemroot%": system_root
    }

    for variable, replacement in replacements.items():

        value = re.sub(
            re.escape(variable),
            lambda _: replacement,
            value,
            flags=re.IGNORECASE
        )

    return value


def normalize_path(path):

    if not path:
        return ""

    path = str(path).strip()

    path = path.strip('"').strip("'")

    path = expand_environment_variables(path)

    system_root = os.environ.get(
        "SystemRoot",
        r"C:\Windows"
    )

    # Handle:
    # \SystemRoot\System32\something.exe

    if path.lower().startswith(
        "\\systemroot\\"
    ):

        remainder = path[
            len("\\SystemRoot\\"):
        ]

        path = os.path.join(
            system_root,
            remainder
        )

    return os.path.normpath(path)


def file_exists(path):

    if not path:
        return False

    try:
        return os.path.isfile(path)

    except Exception:
        return False


# ============================================================
# PROGRAM RESOLUTION
# ============================================================

def resolve_program(program):

    if not program:
        return ""

    program = normalize_path(program)

    if file_exists(program):
        return os.path.abspath(program)

    # Bare executable name.
    # Example:
    # powershell.exe

    if (
        "\\" not in program
        and "/" not in program
    ):

        found = shutil.which(program)

        if found and file_exists(found):

            return os.path.abspath(
                found
            )

    system_root = os.environ.get(
        "SystemRoot",
        r"C:\Windows"
    )

    if (
        "\\" not in program
        and "/" not in program
    ):

        candidates = [
            os.path.join(
                system_root,
                "System32",
                program
            ),

            os.path.join(
                system_root,
                "SysWOW64",
                program
            ),

            os.path.join(
                system_root,
                program
            )
        ]

        for candidate in candidates:

            if file_exists(candidate):

                return os.path.abspath(
                    candidate
                )

    return program


# ============================================================
# COMMAND PARSING
# ============================================================

EXECUTABLE_EXTENSIONS = (
    ".exe",
    ".com",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jse",
    ".wsf"
)


def extract_launcher(command):
    """
    Conservatively extract the primary executable.

    Handles:

        "C:\\Program Files\\Example\\app.exe" --start

        C:\\Program Files\\Example\\app.exe --start

        powershell.exe -File script.ps1

    Does NOT split an unquoted Program Files path at the first
    space.
    """

    if not command:
        return ""

    command = expand_environment_variables(
        str(command).strip()
    )

    if not command:
        return ""

    # --------------------------------------------------------
    # Quoted launcher
    # --------------------------------------------------------

    if command.startswith('"'):

        end_quote = command.find(
            '"',
            1
        )

        if end_quote != -1:

            candidate = command[
                1:end_quote
            ].strip()

            if candidate:

                return resolve_program(
                    candidate
                )

    # --------------------------------------------------------
    # Unquoted launcher
    #
    # Stop at executable extension, not whitespace.
    # --------------------------------------------------------

    match = re.match(
        r"^(.+?\.(?:exe|com|scr|bat|cmd|ps1|vbs|js|jse|wsf))"
        r"(?=\s|$)",
        command,
        flags=re.IGNORECASE
    )

    if match:

        return resolve_program(
            match.group(1).strip()
        )

    # --------------------------------------------------------
    # Bare executable fallback
    # --------------------------------------------------------

    first = command.split()[0]

    if first.lower().endswith(
        EXECUTABLE_EXTENSIONS
    ):

        return resolve_program(
            first
        )

    return ""


def extract_arguments(
    command,
    launcher
):

    if not command or not launcher:
        return ""

    command = expand_environment_variables(
        str(command).strip()
    )

    # Quoted launcher

    if command.startswith('"'):

        end_quote = command.find(
            '"',
            1
        )

        if end_quote != -1:

            return command[
                end_quote + 1:
            ].strip()

    # Unquoted launcher

    match = re.match(
        r"^(.+?\.(?:exe|com|scr|bat|cmd|ps1|vbs|js|jse|wsf))"
        r"(?:\s+(.*))?$",
        command,
        flags=re.IGNORECASE
    )

    if match:

        return (
            match.group(2)
            or ""
        ).strip()

    return ""


# ============================================================
# EXPLICIT TARGET DETECTION
# ============================================================

def resolve_bare_system_dll(target):

    if not target:
        return ""

    target = normalize_path(target)

    if (
        "\\" in target
        or "/" in target
    ):
        return target

    system_root = os.environ.get(
        "SystemRoot",
        r"C:\Windows"
    )

    candidates = [
        os.path.join(
            system_root,
            "System32",
            target
        ),
        os.path.join(
            system_root,
            "SysWOW64",
            target
        )
    ]

    for candidate in candidates:

        if file_exists(candidate):
            return candidate

    return target


def find_explicit_target(
    launcher,
    arguments
):
    """
    Only identify a target when the launcher syntax strongly
    indicates that a particular file is the payload.

    We intentionally DO NOT treat arbitrary command arguments
    as target files.

    This prevents false positives such as:

        Update.exe --processStart "Teams.exe"

    being interpreted as a missing persistence payload.
    """

    if not launcher or not arguments:
        return ""

    launcher_name = os.path.basename(
        launcher
    ).lower()

    arguments = expand_environment_variables(
        arguments
    ).strip()

    # ========================================================
    # PowerShell
    # ========================================================

    if launcher_name in (
        "powershell.exe",
        "pwsh.exe"
    ):

        match = re.search(
            r'(?:^|\s)-(?:file|f)\s+'
            r'(?:"([^"]+)"|([^\s]+))',
            arguments,
            flags=re.IGNORECASE
        )

        if match:

            target = (
                match.group(1)
                or match.group(2)
                or ""
            )

            return normalize_path(
                target
            )

        return ""

    # ========================================================
    # WScript / CScript
    # ========================================================

    if launcher_name in (
        "wscript.exe",
        "cscript.exe"
    ):

        match = re.search(
            r'(?:"([^"]+\.(?:vbs|js|jse|wsf))"'
            r'|([^\s"]+\.(?:vbs|js|jse|wsf)))',
            arguments,
            flags=re.IGNORECASE
        )

        if match:

            target = (
                match.group(1)
                or match.group(2)
                or ""
            )

            return normalize_path(
                target
            )

        return ""

    # ========================================================
    # Rundll32
    # ========================================================

    if launcher_name == "rundll32.exe":

        match = re.search(
            r'(?:"([^"]+\.dll)(?:,[^"]*)?"'
            r'|([^\s,]+\.dll)(?:,[^\s]*)?)',
            arguments,
            flags=re.IGNORECASE
        )

        if match:

            target = (
                match.group(1)
                or match.group(2)
                or ""
            )

            return resolve_bare_system_dll(
                target
            )

        return ""

    # ========================================================
    # Regsvr32
    # ========================================================

    if launcher_name == "regsvr32.exe":

        match = re.search(
            r'(?:"([^"]+\.dll)"'
            r'|([^\s"]+\.dll))',
            arguments,
            flags=re.IGNORECASE
        )

        if match:

            target = (
                match.group(1)
                or match.group(2)
                or ""
            )

            return normalize_path(
                target
            )

        return ""

    # ========================================================
    # CMD
    #
    # Only identify explicit script targets.
    # ========================================================

    if launcher_name == "cmd.exe":

        match = re.search(
            r'(?:^|\s)/(?:c|k)\s+'
            r'(?:"([^"]+\.(?:bat|cmd))"'
            r'|([^\s"]+\.(?:bat|cmd)))',
            arguments,
            flags=re.IGNORECASE
        )

        if match:

            target = (
                match.group(1)
                or match.group(2)
                or ""
            )

            return normalize_path(
                target
            )

    return ""


# ============================================================
# SHA-256
# ============================================================

def calculate_sha256(file_path):

    if not file_path:
        return "N/A"

    file_path = normalize_path(
        file_path
    )

    if not file_exists(file_path):
        return "N/A"

    cache_key = file_path.lower()

    if cache_key in HASH_CACHE:
        return HASH_CACHE[cache_key]

    try:

        sha256 = hashlib.sha256()

        with open(
            file_path,
            "rb"
        ) as file:

            while True:

                chunk = file.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                sha256.update(chunk)

        digest = sha256.hexdigest()

        HASH_CACHE[
            cache_key
        ] = digest

        return digest

    except PermissionError:

        HASH_CACHE[
            cache_key
        ] = "ACCESS_DENIED"

        return "ACCESS_DENIED"

    except OSError:

        HASH_CACHE[
            cache_key
        ] = "ERROR"

        return "ERROR"


# ============================================================
# AUTHENTICODE
# ============================================================

def get_signature_information(
    file_path
):

    default = {
        "Status": "N/A",
        "Publisher": "N/A"
    }

    if not file_path:
        return default

    file_path = normalize_path(
        file_path
    )

    if not file_exists(file_path):
        return default

    cache_key = file_path.lower()

    if cache_key in SIGNATURE_CACHE:

        return SIGNATURE_CACHE[
            cache_key
        ]

    escaped = file_path.replace(
        "'",
        "''"
    )

    command = f"""
$s = Get-AuthenticodeSignature -LiteralPath '{escaped}'

$publisher = ''

if ($s.SignerCertificate) {{
    $publisher = [string]$s.SignerCertificate.Subject
}}

[PSCustomObject]@{{
    Status = [string]$s.Status
    Publisher = $publisher
}} | ConvertTo-Json -Compress
"""

    output = powershell(
        command,
        20
    )

    try:

        data = json.loads(
            output
        )

        status = (
            data.get("Status")
            or "Unknown"
        )

        publisher = (
            data.get("Publisher")
            or ""
        )

        if (
            not publisher
            and status == "NotSigned"
        ):
            publisher = "Unsigned"

        elif not publisher:
            publisher = "Unknown"

        result = {
            "Status": status,
            "Publisher": publisher
        }

    except Exception:

        result = {
            "Status": "Unknown",
            "Publisher": "Unknown"
        }

    SIGNATURE_CACHE[
        cache_key
    ] = result

    return result


# ============================================================
# SHORTCUT RESOLUTION
# ============================================================

def resolve_shortcut(
    shortcut_path
):

    escaped = str(
        shortcut_path
    ).replace(
        "'",
        "''"
    )

    command = f"""
$ws = New-Object -ComObject WScript.Shell
$s = $ws.CreateShortcut('{escaped}')

[PSCustomObject]@{{
    TargetPath = [string]$s.TargetPath
    Arguments  = [string]$s.Arguments
}} | ConvertTo-Json -Compress
"""

    output = powershell(
        command,
        15
    )

    try:

        data = json.loads(
            output
        )

        return (
            data.get(
                "TargetPath"
            )
            or "",
            data.get(
                "Arguments"
            )
            or ""
        )

    except Exception:

        return "", ""


# ============================================================
# PATH CLASSIFICATION
# ============================================================

def path_inside(
    path,
    directory
):

    if not path or not directory:
        return False

    try:

        path = os.path.abspath(
            normalize_path(path)
        )

        directory = os.path.abspath(
            normalize_path(directory)
        )

        return (
            os.path.commonpath(
                [path, directory]
            ).lower()
            ==
            directory.lower()
        )

    except Exception:

        return False


def is_temp_path(path):

    if not path:
        return False

    for variable in (
        "TEMP",
        "TMP"
    ):

        location = os.environ.get(
            variable,
            ""
        )

        if (
            location
            and path_inside(
                path,
                location
            )
        ):
            return True

    return False


def is_downloads_path(path):

    profile = os.environ.get(
        "USERPROFILE",
        ""
    )

    if not profile:
        return False

    return path_inside(
        path,
        os.path.join(
            profile,
            "Downloads"
        )
    )


def is_roaming_appdata(path):

    location = os.environ.get(
        "APPDATA",
        ""
    )

    return (
        bool(location)
        and path_inside(
            path,
            location
        )
    )


def is_local_appdata(path):

    location = os.environ.get(
        "LOCALAPPDATA",
        ""
    )

    return (
        bool(location)
        and path_inside(
            path,
            location
        )
    )


def is_network_path(path):

    if not path:
        return False

    return str(path).startswith(
        "\\\\"
    )


def is_user_writable_location(
    path
):

    if not path:
        return False

    locations = [
        os.environ.get(
            "USERPROFILE",
            ""
        ),
        os.environ.get(
            "TEMP",
            ""
        ),
        os.environ.get(
            "TMP",
            ""
        )
    ]

    for location in locations:

        if (
            location
            and path_inside(
                path,
                location
            )
        ):
            return True

    return False


# ============================================================
# MICROSOFT SIGNATURE CHECK
# ============================================================

def is_microsoft_publisher(
    publisher
):

    if not publisher:
        return False

    publisher = publisher.lower()

    return (
        "microsoft corporation"
        in publisher
        or
        "microsoft windows"
        in publisher
    )


# ============================================================
# FLAGS + WEIGHTS
# ============================================================

# Conservative scoring:
#
# 0        CLEAN
# 1-2      LOW
# 3-5      MEDIUM
# 6+       HIGH
#
# Strong behaviors carry most of the score.
# Common characteristics carry very little.


FLAG_SCORES = {

    # --------------------------------------------------------
    # Strong indicators
    # --------------------------------------------------------

    "TEMP_PATH": 5,

    "DOWNLOADS_PATH": 5,

    "ENCODED_COMMAND": 5,

    "HIDDEN_WINDOW": 4,

    # --------------------------------------------------------
    # Moderate indicators
    # --------------------------------------------------------

    "NETWORK_PATH": 3,

    "SYSTEM_USER_WRITABLE": 3,

    "MISSING_FILE": 2,

    "MSHTA": 2,

    # --------------------------------------------------------
    # Weak indicators
    # --------------------------------------------------------

    "POWERSHELL": 1,

    "CMD": 1,

    "RUNDLL32": 1,

    "REGSVR32": 1,

    "WSCRIPT": 1,

    "CSCRIPT": 1,

    "SCRIPT": 1,

    "APPDATA": 1,

    "LOCAL_APPDATA": 1,

    "UNSIGNED": 1
}


# ============================================================
# FLAG DETECTION
# ============================================================

def detect_flags(
    scope,
    startup_type,
    launcher,
    target,
    command,
    launcher_signature,
    target_signature
):

    flags = []

    launcher_name = (
        os.path.basename(
            launcher
        ).lower()
        if launcher
        else ""
    )

    analysis_path = (
        target
        if target
        else launcher
    )

    command_lower = (
        command or ""
    ).lower()

    # ========================================================
    # LOCATION FLAGS
    # ========================================================

    if (
        analysis_path
        and is_temp_path(
            analysis_path
        )
    ):

        flags.append(
            "TEMP_PATH"
        )

    if (
        analysis_path
        and is_downloads_path(
            analysis_path
        )
    ):

        flags.append(
            "DOWNLOADS_PATH"
        )

    if (
        analysis_path
        and is_roaming_appdata(
            analysis_path
        )
    ):

        flags.append(
            "APPDATA"
        )

    elif (
        analysis_path
        and is_local_appdata(
            analysis_path
        )
    ):

        flags.append(
            "LOCAL_APPDATA"
        )

    if (
        analysis_path
        and is_network_path(
            analysis_path
        )
    ):

        flags.append(
            "NETWORK_PATH"
        )

    # ========================================================
    # INTERPRETERS / LOLBINS
    # ========================================================

    if launcher_name in (
        "powershell.exe",
        "pwsh.exe"
    ):

        flags.append(
            "POWERSHELL"
        )

    elif launcher_name == "cmd.exe":

        flags.append(
            "CMD"
        )

    elif launcher_name == "rundll32.exe":

        flags.append(
            "RUNDLL32"
        )

    elif launcher_name == "regsvr32.exe":

        flags.append(
            "REGSVR32"
        )

    elif launcher_name == "mshta.exe":

        flags.append(
            "MSHTA"
        )

    elif launcher_name == "wscript.exe":

        flags.append(
            "WSCRIPT"
        )

    elif launcher_name == "cscript.exe":

        flags.append(
            "CSCRIPT"
        )

    # ========================================================
    # SCRIPT
    # ========================================================

    if (
        analysis_path
        and analysis_path.lower().endswith(
            (
                ".ps1",
                ".bat",
                ".cmd",
                ".vbs",
                ".js",
                ".jse",
                ".wsf"
            )
        )
    ):

        flags.append(
            "SCRIPT"
        )

    # ========================================================
    # POWERSHELL BEHAVIOR
    # ========================================================

    if launcher_name in (
        "powershell.exe",
        "pwsh.exe"
    ):

        encoded_patterns = [
            r"(?:^|\s)-encodedcommand(?:\s|$)",
            r"(?:^|\s)-enc(?:\s|$)"
        ]

        if any(
            re.search(
                pattern,
                command_lower,
                re.IGNORECASE
            )
            for pattern in encoded_patterns
        ):

            flags.append(
                "ENCODED_COMMAND"
            )

        hidden_patterns = (
            "-windowstyle hidden",
            "-windowstyle:hidden",
            "-w hidden"
        )

        if any(
            pattern in command_lower
            for pattern in hidden_patterns
        ):

            flags.append(
                "HIDDEN_WINDOW"
            )

    # ========================================================
    # SYSTEM PERSISTENCE -> USER-WRITABLE LOCATION
    # ========================================================

    if (
        scope
        in (
            "All Users",
            "System / All Users"
        )
        and analysis_path
        and is_user_writable_location(
            analysis_path
        )
    ):

        flags.append(
            "SYSTEM_USER_WRITABLE"
        )

    # ========================================================
    # MISSING FILE
    #
    # Only use actual resolved path-like references.
    # Bare optional names are not flagged.
    # ========================================================

    if launcher:

        path_like = (
            "\\" in launcher
            or "/" in launcher
        )

        if (
            path_like
            and not file_exists(
                launcher
            )
        ):

            flags.append(
                "MISSING_FILE"
            )

    if target:

        target_path_like = (
            "\\" in target
            or "/" in target
        )

        if (
            target_path_like
            and not file_exists(
                target
            )
        ):

            flags.append(
                "MISSING_FILE"
            )

    # ========================================================
    # UNSIGNED
    #
    # Weak indicator only.
    #
    # Prefer target signature when a target exists.
    # ========================================================

    if target:

        signature = (
            target_signature
        )

    else:

        signature = (
            launcher_signature
        )

    if (
        signature.get("Status")
        == "NotSigned"
    ):

        flags.append(
            "UNSIGNED"
        )

    # Remove duplicates while preserving order.

    return list(
        dict.fromkeys(
            flags
        )
    )


# ============================================================
# CONSERVATIVE SCORE CALCULATION
# ============================================================

def calculate_risk_score(
    flags,
    launcher_publisher,
    target_publisher
):

    score = sum(
        FLAG_SCORES.get(
            flag,
            0
        )
        for flag in flags
    )

    # ========================================================
    # FALSE-POSITIVE REDUCTION
    #
    # Microsoft-signed Windows components commonly use
    # rundll32, PowerShell, cmd, etc.
    #
    # Do not completely remove the flag.
    # Instead reduce weak interpreter-only scoring.
    # ========================================================

    publisher = (
        target_publisher
        if (
            target_publisher
            and target_publisher
            not in (
                "N/A",
                "Unknown",
                "Unsigned"
            )
        )
        else launcher_publisher
    )

    microsoft_signed = (
        is_microsoft_publisher(
            publisher
        )
    )

    strong_flags = {
        "TEMP_PATH",
        "DOWNLOADS_PATH",
        "ENCODED_COMMAND",
        "HIDDEN_WINDOW",
        "NETWORK_PATH",
        "SYSTEM_USER_WRITABLE"
    }

    has_strong_flag = bool(
        set(flags)
        & strong_flags
    )

    weak_interpreter_flags = {
        "POWERSHELL",
        "CMD",
        "RUNDLL32",
        "REGSVR32",
        "WSCRIPT",
        "CSCRIPT"
    }

    if (
        microsoft_signed
        and not has_strong_flag
    ):

        weak_count = len(
            set(flags)
            & weak_interpreter_flags
        )

        score -= weak_count

    return max(
        score,
        0
    )


# ============================================================
# SEVERITY
# ============================================================

def get_severity(score):

    if score >= 6:
        return "HIGH"

    if score >= 3:
        return "MEDIUM"

    if score >= 1:
        return "LOW"

    return "CLEAN"


# ============================================================
# RESULT CREATION
# ============================================================

def add_result(
    name,
    scope,
    startup_type,
    command,
    launcher="",
    arguments=""
):

    command = str(
        command or ""
    ).strip()

    launcher = str(
        launcher or ""
    ).strip()

    arguments = str(
        arguments or ""
    ).strip()

    # ========================================================
    # LAUNCHER
    # ========================================================

    if launcher:

        launcher = resolve_program(
            launcher
        )

    else:

        launcher = extract_launcher(
            command
        )

    # ========================================================
    # ARGUMENTS
    # ========================================================

    if (
        launcher
        and not arguments
    ):

        arguments = extract_arguments(
            command,
            launcher
        )

    # ========================================================
    # TARGET
    # ========================================================

    target = find_explicit_target(
        launcher,
        arguments
    )

    # ========================================================
    # EXISTENCE
    # ========================================================

    launcher_exists = (
        file_exists(
            launcher
        )
        if launcher
        else False
    )

    target_exists = (
        file_exists(
            target
        )
        if target
        else False
    )

    # ========================================================
    # SIGNATURES
    # ========================================================

    if launcher_exists:

        launcher_signature = (
            get_signature_information(
                launcher
            )
        )

    else:

        launcher_signature = {
            "Status": "N/A",
            "Publisher": "N/A"
        }

    if target_exists:

        target_signature = (
            get_signature_information(
                target
            )
        )

    else:

        target_signature = {
            "Status": "N/A",
            "Publisher": "N/A"
        }

    # ========================================================
    # HASHES
    # ========================================================

    launcher_hash = (
        calculate_sha256(
            launcher
        )
        if launcher_exists
        else "N/A"
    )

    target_hash = (
        calculate_sha256(
            target
        )
        if target_exists
        else "N/A"
    )

    # ========================================================
    # FLAGS
    # ========================================================

    flags = detect_flags(
        scope,
        startup_type,
        launcher,
        target,
        command,
        launcher_signature,
        target_signature
    )

    # ========================================================
    # SCORE
    # ========================================================

    score = calculate_risk_score(
        flags,
        launcher_signature[
            "Publisher"
        ],
        target_signature[
            "Publisher"
        ]
    )

    severity = get_severity(
        score
    )

    # ========================================================
    # SAVE RESULT
    # ========================================================

    results.append(
        {
            "Name":
                str(name),

            "Scope":
                str(scope),

            "Startup Type":
                str(startup_type),

            "Command":
                command,

            "Arguments":
                arguments,

            "Launcher":
                (
                    launcher
                    if launcher
                    else "N/A"
                ),

            "Launcher Exists":
                (
                    "YES"
                    if launcher_exists
                    else (
                        "NO"
                        if launcher
                        else "N/A"
                    )
                ),

            "Launcher Publisher":
                launcher_signature[
                    "Publisher"
                ],

            "Launcher Signature":
                launcher_signature[
                    "Status"
                ],

            "Launcher SHA-256":
                launcher_hash,

            "Target":
                (
                    target
                    if target
                    else "N/A"
                ),

            "Target Exists":
                (
                    "YES"
                    if target_exists
                    else (
                        "NO"
                        if target
                        else "N/A"
                    )
                ),

            "Target Publisher":
                target_signature[
                    "Publisher"
                ],

            "Target Signature":
                target_signature[
                    "Status"
                ],

            "Target SHA-256":
                target_hash,

            "Score":
                score,

            "Severity":
                severity,

            "Flags":
                (
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
    folder,
    scope
):

    path = Path(folder)

    if not path.exists():
        return

    try:

        for entry in path.iterdir():

            if not entry.is_file():
                continue

            # =================================================
            # SHORTCUT
            # =================================================

            if (
                entry.suffix.lower()
                == ".lnk"
            ):

                target, arguments = (
                    resolve_shortcut(
                        entry
                    )
                )

                if not target:
                    continue

                command = (
                    f'"{target}"'
                )

                if arguments:

                    command += (
                        f" {arguments}"
                    )

                add_result(
                    entry.name,
                    scope,
                    "Startup Folder",
                    command,
                    target,
                    arguments
                )

            # =================================================
            # DIRECT FILE
            # =================================================

            else:

                add_result(
                    entry.name,
                    scope,
                    "Startup Folder",
                    str(entry),
                    str(entry),
                    ""
                )

    except PermissionError:

        print(
            YELLOW
            + f"[!] Access denied: {folder}"
            + RESET
        )


# ============================================================
# REGISTRY
# ============================================================

def scan_registry_key(
    hive,
    key_path,
    scope,
    startup_type,
    view_flag=0
):

    try:

        access = (
            winreg.KEY_READ
            | view_flag
        )

        with winreg.OpenKey(
            hive,
            key_path,
            0,
            access
        ) as key:

            index = 0

            while True:

                try:

                    name, value, _ = (
                        winreg.EnumValue(
                            key,
                            index
                        )
                    )

                    add_result(
                        name,
                        scope,
                        startup_type,
                        str(value)
                    )

                    index += 1

                except OSError:
                    break

    except (
        FileNotFoundError,
        PermissionError,
        OSError
    ):
        pass


def scan_registry():

    locations = [
        (
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "Registry Run"
        ),
        (
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "Registry RunOnce"
        )
    ]

    # Current User

    for key, startup_type in locations:

        scan_registry_key(
            winreg.HKEY_CURRENT_USER,
            key,
            "Current User",
            startup_type
        )

    # HKLM 64-bit

    for key, startup_type in locations:

        scan_registry_key(
            winreg.HKEY_LOCAL_MACHINE,
            key,
            "All Users",
            startup_type
            + " (64-bit)",
            winreg.KEY_WOW64_64KEY
        )

    # HKLM 32-bit

    for key, startup_type in locations:

        scan_registry_key(
            winreg.HKEY_LOCAL_MACHINE,
            key,
            "All Users",
            startup_type
            + " (32-bit)",
            winreg.KEY_WOW64_32KEY
        )


# ============================================================
# SCHEDULED TASKS
# ============================================================

def scan_scheduled_tasks():

    command = r"""
$items = @()

foreach ($task in Get-ScheduledTask -ErrorAction SilentlyContinue) {

    foreach ($action in $task.Actions) {

        $execute = ''
        $arguments = ''

        if ($null -ne $action.Execute) {
            $execute = [string]$action.Execute
        }

        if ($null -ne $action.Arguments) {
            $arguments = [string]$action.Arguments
        }

        $items += [PSCustomObject]@{
            TaskName  = [string]$task.TaskName
            TaskPath  = [string]$task.TaskPath
            State     = [string]$task.State
            UserId    = [string]$task.Principal.UserId
            RunLevel  = [string]$task.Principal.RunLevel
            Execute   = $execute
            Arguments = $arguments
        }
    }
}

$items | ConvertTo-Json -Compress -Depth 4
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

    if isinstance(
        tasks,
        dict
    ):
        tasks = [tasks]

    username = os.environ.get(
        "USERNAME",
        ""
    ).lower()

    for task in tasks:

        execute = str(
            task.get(
                "Execute",
                ""
            )
            or ""
        ).strip()

        arguments = str(
            task.get(
                "Arguments",
                ""
            )
            or ""
        ).strip()

        user_id = str(
            task.get(
                "UserId",
                ""
            )
            or ""
        )

        task_name = str(
            task.get(
                "TaskName",
                "Unknown"
            )
        )

        task_path = str(
            task.get(
                "TaskPath",
                "\\"
            )
        )

        # Do not manufacture a launcher from metadata
        # when the task does not have an executable action.

        if not execute:
            continue

        if (
            username
            and username
            in user_id.lower()
        ):

            scope = "Current User"

        else:

            scope = "System / All Users"

        command_line = (
            f'"{execute}"'
        )

        if arguments:

            command_line += (
                f" {arguments}"
            )

        add_result(
            f"{task_path}{task_name}",
            scope,
            "Scheduled Task",
            command_line,
            execute,
            arguments
        )


# ============================================================
# AUTOMATIC SERVICES
# ============================================================

def scan_services():

    command = r"""
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
Where-Object {
    $_.StartMode -eq 'Auto'
} |
Select-Object Name,DisplayName,StartMode,State,StartName,PathName |
ConvertTo-Json -Compress -Depth 4
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

    if isinstance(
        services,
        dict
    ):
        services = [services]

    for service in services:

        service_name = str(
            service.get(
                "Name",
                "Unknown"
            )
        )

        display_name = str(
            service.get(
                "DisplayName",
                service_name
            )
        )

        path_name = str(
            service.get(
                "PathName",
                ""
            )
            or ""
        ).strip()

        if not path_name:
            continue

        add_result(
            (
                f"{display_name} "
                f"[{service_name}]"
            ),
            "System / All Users",
            "Service (Auto)",
            path_name
        )


# ============================================================
# DISPLAY HELPERS
# ============================================================

def shorten(
    value,
    length
):

    value = str(value)

    if len(value) <= length:
        return value

    return (
        value[:length - 3]
        + "..."
    )


def severity_color(
    severity
):

    if severity == "HIGH":
        return RED

    if severity == "MEDIUM":
        return YELLOW

    if severity == "LOW":
        return MAGENTA

    return GREEN


# ============================================================
# RESULTS TABLE
# ============================================================

def print_table():

    if not results:

        print(
            "\nNo persistence entries found."
        )

        return

    print()

    print(
        BOLD
        + CYAN
        + "=" * 174
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
        + "=" * 174
        + RESET
    )

    headers = [
        ("Severity", 9),
        ("Score", 6),
        ("Name", 31),
        ("Scope", 18),
        ("Startup Type", 23),
        ("Launcher", 38),
        ("Publisher", 25),
        ("Flags", 40)
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

    print(
        "-" * 174
    )

    for item in results:

        values = {
            "Severity":
                item["Severity"],

            "Score":
                str(item["Score"]),

            "Name":
                item["Name"],

            "Scope":
                item["Scope"],

            "Startup Type":
                item["Startup Type"],

            "Launcher":
                item["Launcher"],

            "Publisher":
                item[
                    "Launcher Publisher"
                ],

            "Flags":
                item["Flags"]
        }

        line = ""

        for header, width in headers:

            line += (
                f"{shorten(values[header], width):<{width}} "
            )

        print(
            severity_color(
                item["Severity"]
            )
            + line
            + RESET
        )

    print(
        "=" * 174
    )


# ============================================================
# SUMMARY
# ============================================================

def print_summary():

    counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "CLEAN": 0
    }

    for item in results:

        counts[
            item["Severity"]
        ] += 1

    print(
        "\n"
        + BOLD
        + CYAN
        + "SCAN SUMMARY"
        + RESET
    )

    print(
        "=" * 60
    )

    print(
        f"Total entries      : "
        f"{len(results)}"
    )

    print(
        RED
        + f"High priority      : "
        f"{counts['HIGH']}"
        + RESET
    )

    print(
        YELLOW
        + f"Medium priority    : "
        f"{counts['MEDIUM']}"
        + RESET
    )

    print(
        MAGENTA
        + f"Low priority       : "
        f"{counts['LOW']}"
        + RESET
    )

    print(
        GREEN
        + f"No heuristic flags : "
        f"{counts['CLEAN']}"
        + RESET
    )

    print()

    print(
        "Risk thresholds:"
    )

    print(
        "  CLEAN  = 0"
    )

    print(
        "  LOW    = 1-2"
    )

    print(
        "  MEDIUM = 3-5"
    )

    print(
        "  HIGH   = 6+"
    )

    print()

    print(
        "Flags are heuristic indicators, not malware verdicts."
    )


# ============================================================
# HASH ANALYSIS
# ============================================================

def valid_sha256(value):

    if not isinstance(
        value,
        str
    ):
        return False

    return bool(
        re.fullmatch(
            r"[0-9a-fA-F]{64}",
            value
        )
    )


def print_hash_analysis():

    launcher_hashes = 0
    target_hashes = 0
    unavailable = 0
    errors = 0

    for item in results:

        launcher_hash = item[
            "Launcher SHA-256"
        ]

        target_hash = item[
            "Target SHA-256"
        ]

        if valid_sha256(
            launcher_hash
        ):

            launcher_hashes += 1

        elif launcher_hash in (
            "ACCESS_DENIED",
            "ERROR"
        ):

            errors += 1

        elif (
            item["Launcher"]
            != "N/A"
        ):

            unavailable += 1

        if valid_sha256(
            target_hash
        ):

            target_hashes += 1

    print(
        "\n"
        + BOLD
        + CYAN
        + "HASH ANALYSIS"
        + RESET
    )

    print(
        "=" * 60
    )

    print(
        f"Launcher hashes calculated : "
        f"{launcher_hashes}"
    )

    print(
        f"Target hashes calculated   : "
        f"{target_hashes}"
    )

    print(
        f"Unavailable paths          : "
        f"{unavailable}"
    )

    print(
        f"Hash/access errors         : "
        f"{errors}"
    )


# ============================================================
# FLAGGED ENTRY DETAILS
# ============================================================

def print_flagged_details():

    flagged = [
        item
        for item in results
        if item["Severity"]
        != "CLEAN"
    ]

    if not flagged:

        print(
            "\n"
            + GREEN
            + "No entries triggered risk flags."
            + RESET
        )

        return

    print(
        "\n"
        + BOLD
        + CYAN
        + "FLAGGED ENTRY DETAILS"
        + RESET
    )

    print(
        "=" * 100
    )

    for number, item in enumerate(
        flagged,
        1
    ):

        color = severity_color(
            item["Severity"]
        )

        print(
            f"\n{color}"
            f"[{number}] "
            f"{item['Severity']} "
            f"(Score {item['Score']}) - "
            f"{item['Name']}"
            f"{RESET}"
        )

        print(
            "-" * 100
        )

        print(
            f"Scope              : "
            f"{item['Scope']}"
        )

        print(
            f"Startup Type       : "
            f"{item['Startup Type']}"
        )

        print(
            f"Command            : "
            f"{item['Command']}"
        )

        print(
            f"Arguments          : "
            f"{item['Arguments']}"
        )

        print()

        print(
            f"Launcher           : "
            f"{item['Launcher']}"
        )

        print(
            f"Launcher Exists    : "
            f"{item['Launcher Exists']}"
        )

        print(
            f"Launcher Publisher : "
            f"{item['Launcher Publisher']}"
        )

        print(
            f"Launcher Signature : "
            f"{item['Launcher Signature']}"
        )

        print(
            f"Launcher SHA-256   : "
            f"{item['Launcher SHA-256']}"
        )

        print()

        print(
            f"Target             : "
            f"{item['Target']}"
        )

        print(
            f"Target Exists      : "
            f"{item['Target Exists']}"
        )

        print(
            f"Target Publisher   : "
            f"{item['Target Publisher']}"
        )

        print(
            f"Target Signature   : "
            f"{item['Target Signature']}"
        )

        print(
            f"Target SHA-256     : "
            f"{item['Target SHA-256']}"
        )

        print()

        print(
            f"Risk Score         : "
            f"{item['Score']}"
        )

        print(
            f"Flags              : "
            f"{color}"
            f"{item['Flags']}"
            f"{RESET}"
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
        + " WINDOWS PERSISTENCE SCANNER"
        + RESET
    )

    print(
        BOLD
        + CYAN
        + "=" * 80
        + RESET
    )

    # ========================================================
    # STARTUP FOLDERS
    # ========================================================

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

    # ========================================================
    # REGISTRY
    # ========================================================

    print(
        "[*] Scanning Registry Run / RunOnce..."
    )

    scan_registry()

    # ========================================================
    # SCHEDULED TASKS
    # ========================================================

    print(
        "[*] Scanning Scheduled Tasks..."
    )

    scan_scheduled_tasks()

    # ========================================================
    # SERVICES
    # ========================================================

    print(
        "[*] Scanning Automatic Windows Services..."
    )

    scan_services()

    # ========================================================
    # RESULTS
    # ========================================================

    print(
        "[*] Resolving files, signatures, and SHA-256 hashes..."
    )

    priority = {
        "HIGH": 0,
        "MEDIUM": 1,
        "LOW": 2,
        "CLEAN": 3
    }

    results.sort(
        key=lambda item: (
            priority.get(
                item["Severity"],
                4
            ),

            -item["Score"],

            item[
                "Startup Type"
            ].lower(),

            item[
                "Name"
            ].lower()
        )
    )

    print_table()

    print_summary()

    print_hash_analysis()

    print_flagged_details()


if __name__ == "__main__":
    main()
