import re
from typing import List, Tuple

# Suspicious keywords in command line or process names
SUSPICIOUS_CMD_PATTERNS = [
    (r"(?:-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{10,}", "Encoded PowerShell Command Execution"),
    (r"-w\s+hidden|-windowstyle\s+hidden", "Hidden Window Process Spawning"),
    (r"-ep\s+bypass|-executionpolicy\s+bypass", "PowerShell Execution Policy Bypass"),
    (r"vssadmin(?:\.exe)?\s+delete\s+shadows", "Ransomware Shadow Copy Deletion"),
    (r"bcdedit(?:\.exe)?\s+.*recoveryenabled\s+no", "System Recovery Invalidation"),
    (r"certutil(?:\.exe)?\s+-(?:urlcache|decode)", "Living-off-the-Land Binary (LOLBIN) Payload Retrieval"),
    (r"whoami(?:\.exe)?\s+/all", "Reconnaissance Discovery"),
    (r"mimikatz|lazagne", "Credential Dumping Tool Match"),
    (r"xmrig|minergate|stratum\+tcp", "Cryptocurrency Mining Indicator"),
    (r"downloadstring\s*\(|downloadfile\s*\(|invoke-webrequest", "In-Memory Payload Ingestion"),
    (r"iex\s*\(|invoke-expression", "Direct Memory Script Execution Wrapper"),
    (r"rundll32(?:\.exe)?\s+.*,\s*(?:#\d+|DllRegisterServer|Execute)", "Rundll32 DLL Execution Pattern")
]

SUSPICIOUS_PORTS = {4444, 1337, 6667, 31337, 8888, 9001, 7777, 5555}

DOUBLE_EXTENSION_PATTERN = re.compile(
    r"\.(?:pdf|docx|xlsx|txt|jpg|png|doc|xls|rtf)\.(?:exe|vbs|bat|cmd|ps1|scr|pif|hta)$",
    re.IGNORECASE
)

SUSPICIOUS_SCRIPT_EXTENSIONS = {
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".ps1", ".bat", ".cmd", ".scr", ".pif"
}

def evaluate_process_heuristics(name: str, path: str, cmdline: str) -> Tuple[bool, List[str]]:
    reasons = []
    name_lower = (name or "").lower()
    path_lower = (path or "").lower()
    cmd_lower = (cmdline or "").lower()

    # 1. Unusual execution location (Temp or AppData)
    if "appdata\\local\\temp" in path_lower or "\\windows\\temp" in path_lower:
        reasons.append("Process executing directly from temporary directory (Temp)")
    elif "\\appdata\\roaming\\" in path_lower and not any(k in path_lower for k in ["microsoft", "adobe", "google", "brave", "mozilla"]):
        reasons.append("Process running from non-standard AppData\\Roaming path")

    # 2. Typosquatting / Process Masquerading
    typosquats = ["svch0st", "lsasss", "csrsss", "smss1", "services32", "conh0st", "explorer32"]
    for ts in typosquats:
        if ts in name_lower:
            reasons.append(f"Process masquerading / typosquatting detected ({ts})")

    # 3. Known attack tools
    for tool in ["mimikatz", "xmrig", "nc.exe", "ncat.exe", "chisel", "ngrok"]:
        if tool in name_lower:
            reasons.append(f"Known attack / tunneling tool binary name ({tool})")

    # 4. Command Line Inspection
    for pattern, desc in SUSPICIOUS_CMD_PATTERNS:
        if re.search(pattern, cmd_lower, re.IGNORECASE):
            reasons.append(desc)

    return (len(reasons) > 0, reasons)


def evaluate_persistence_heuristics(name: str, location: str, command: str) -> Tuple[bool, List[str]]:
    reasons = []
    cmd_lower = (command or "").lower()

    if "temp\\" in cmd_lower or "appdata\\local\\temp" in cmd_lower:
        reasons.append("Persistence entry points to temporary directory (Temp)")

    for ext in SUSPICIOUS_SCRIPT_EXTENSIONS:
        if ext in cmd_lower:
            reasons.append(f"Persistence executes raw script file ({ext})")
            break

    if "powershell" in cmd_lower and any(flag in cmd_lower for flag in ["-enc", "-w hidden", "-ep bypass"]):
        reasons.append("Persistence launches obfuscated / hidden PowerShell payload")

    if "wscript" in cmd_lower or "cscript" in cmd_lower or "mshta" in cmd_lower:
        reasons.append("Persistence invokes Windows Script Host or MSHTA")

    return (len(reasons) > 0, reasons)


def evaluate_service_heuristics(name: str, display_name: str, binary_path: str) -> Tuple[bool, List[str]]:
    reasons = []
    bin_lower = (binary_path or "").lower()

    if "users\\" in bin_lower or "temp\\" in bin_lower or "appdata\\" in bin_lower:
        reasons.append("Service binary hosted in user-writable directory (Temp/AppData/Users)")

    if any(ext in bin_lower for ext in [".vbs", ".bat", ".cmd", ".ps1"]):
        reasons.append("Service directly triggers script interpreter")

    if "powershell" in bin_lower and ("-enc" in bin_lower or "-w hidden" in bin_lower):
        reasons.append("Service executes hidden encoded script")

    return (len(reasons) > 0, reasons)


def evaluate_scheduled_task_heuristics(name: str, path: str, action: str) -> Tuple[bool, List[str]]:
    reasons = []
    action_lower = (action or "").lower()
    path_lower = (path or "").lower()

    if "users\\" in action_lower or "temp\\" in action_lower or "appdata\\" in action_lower:
        reasons.append("Scheduled task target resides in user profile / Temp folder")

    for pattern, desc in SUSPICIOUS_CMD_PATTERNS:
        if re.search(pattern, action_lower, re.IGNORECASE):
            reasons.append(f"Task action: {desc}")

    # Flag tasks registered in root or unusual non-Windows folders executing scripts
    if not path_lower.startswith("\\microsoft\\windows"):
        if any(ext in action_lower for ext in [".vbs", ".bat", ".cmd", ".ps1", ".hta"]):
            reasons.append("Third-party task triggers script file directly")

    return (len(reasons) > 0, reasons)


def evaluate_network_heuristics(remote_addr: str, remote_port: int, process_name: str) -> Tuple[bool, List[str]]:
    reasons = []
    p_lower = (process_name or "").lower()

    if remote_port in SUSPICIOUS_PORTS:
        reasons.append(f"Outbound connection on known attack / reverse shell port ({remote_port})")

    if remote_addr in ["127.0.0.1", "0.0.0.0", "::1"]:
        return (False, [])

    # Command shells establishing direct foreign network sockets
    if any(shell in p_lower for shell in ["cmd.exe", "powershell.exe", "powershell_ise.exe", "wscript.exe", "cscript.exe"]):
        reasons.append(f"Command shell interpreter ({process_name}) actively maintaining foreign network connection")

    return (len(reasons) > 0, reasons)


def evaluate_file_heuristics(file_name: str, file_path: str, size_bytes: int) -> Tuple[bool, List[str]]:
    reasons = []
    name_lower = file_name.lower()
    path_lower = file_path.lower()

    # 1. Double extension check (e.g. Invoice.pdf.exe)
    if DOUBLE_EXTENSION_PATTERN.search(name_lower):
        reasons.append("Masquerading double file extension detected (e.g. document disguised as executable)")

    # 2. Suspicious extensions in Temp or Downloads
    ext = "." + name_lower.split(".")[-1] if "." in name_lower else ""
    if ext in SUSPICIOUS_SCRIPT_EXTENSIONS:
        if "temp" in path_lower or "downloads" in path_lower:
            reasons.append(f"Potentially dangerous script file ({ext}) located in volatile directory")

    if ext in [".scr", ".pif", ".hta", ".cpl"]:
        reasons.append(f"High-risk legacy executable format ({ext})")

    return (len(reasons) > 0, reasons)
