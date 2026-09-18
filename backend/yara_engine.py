import re
from typing import Dict, List, Any

DEFAULT_YARA_RULES = [
    {
        "id": "rule_ransomware_shadow_deletion",
        "name": "Ransomware_VSS_Deletion",
        "category": "Ransomware",
        "severity": "CRITICAL",
        "meta": {
            "author": "Antigravity Threat Lab",
            "description": "Detects shadow copy deletion commands used by ransomware families (WannaCry, LockBit, Conti)",
            "threat_level": 95
        },
        "strings": [
            "vssadmin.exe delete shadows",
            "wmic shadowcopy delete",
            "bcdedit /set {default} recoveryenabled No",
            "wbadmin delete catalog -quiet"
        ],
        "condition": "any of ($strings)"
    },
    {
        "id": "rule_process_injection",
        "name": "Process_Injection_Memory_Patching",
        "category": "Defense Evasion",
        "severity": "HIGH",
        "meta": {
            "author": "Antigravity Threat Lab",
            "description": "Detects remote process memory allocation and thread creation (Cobalt Strike, Meterpreter)",
            "threat_level": 88
        },
        "strings": [
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtUnmapViewOfSection"
        ],
        "condition": "VirtualAllocEx and WriteProcessMemory and CreateRemoteThread"
    },
    {
        "id": "rule_infostealer_browser",
        "name": "Infostealer_Browser_Credential_Harvesting",
        "category": "Credential Access",
        "severity": "HIGH",
        "meta": {
            "author": "Antigravity Threat Lab",
            "description": "Detects access to Chrome, Firefox, or Edge login data databases and DPAPI decryption",
            "threat_level": 82
        },
        "strings": [
            "Login Data",
            "CryptUnprotectData",
            "sqlite3_open",
            "SELECT origin_url, username_value, password_value FROM logins"
        ],
        "condition": "Login Data and CryptUnprotectData"
    },
    {
        "id": "rule_webshell_php",
        "name": "WebShell_PHP_Generic_Command_Execution",
        "category": "WebShell",
        "severity": "CRITICAL",
        "meta": {
            "author": "Antigravity Threat Lab",
            "description": "Detects PHP webshell execution functions (eval, system, passthru, shell_exec)",
            "threat_level": 90
        },
        "strings": [
            "eval(base64_decode(",
            "shell_exec($_POST",
            "passthru($_GET",
            "system($_REQUEST"
        ],
        "condition": "any of ($strings)"
    },
    {
        "id": "rule_keylogger_rawinput",
        "name": "Keylogger_Windows_Hook_AsyncKeyState",
        "category": "Spyware",
        "severity": "MEDIUM",
        "meta": {
            "author": "Antigravity Threat Lab",
            "description": "Detects Windows keyboard polling or WH_KEYBOARD_LL hooks",
            "threat_level": 65
        },
        "strings": [
            "GetAsyncKeyState",
            "SetWindowsHookExA",
            "WH_KEYBOARD_LL",
            "GetForegroundWindow"
        ],
        "condition": "GetAsyncKeyState or SetWindowsHookExA"
    },
    {
        "id": "rule_reverse_shell_powershell",
        "name": "PowerShell_Encoded_Reverse_Shell",
        "category": "Command & Control",
        "severity": "HIGH",
        "meta": {
            "author": "Antigravity Threat Lab",
            "description": "Detects obfuscated PowerShell TCP client sockets and hidden execution flags",
            "threat_level": 85
        },
        "strings": [
            "powershell -nop -w hidden -enc",
            "System.Net.Sockets.TCPClient",
            "DownloadString('http",
            "IEX (New-Object Net.WebClient)"
        ],
        "condition": "any of ($strings)"
    }
]

class YaraEngine:
    def __init__(self):
        self.rules = DEFAULT_YARA_RULES.copy()

    def get_rules(self) -> List[Dict[str, Any]]:
        return self.rules

    def add_custom_rule(self, rule_name: str, category: str, strings: List[str], condition: str) -> Dict[str, Any]:
        new_rule = {
            "id": f"rule_custom_{len(self.rules) + 1}",
            "name": rule_name.replace(" ", "_"),
            "category": category,
            "severity": "HIGH",
            "meta": {
                "author": "User Submission",
                "description": "User created custom YARA signature",
                "threat_level": 75
            },
            "strings": strings,
            "condition": condition
        }
        self.rules.append(new_rule)
        return new_rule

    def scan(self, content: bytes) -> Dict[str, Any]:
        matched_rules = []
        content_str = content.decode("ascii", errors="ignore")
        content_lower = content_str.lower()

        for rule in self.rules:
            matched_strings = []
            for s in rule["strings"]:
                if s.lower() in content_lower:
                    matched_strings.append(s)

            # Check condition logic
            is_matched = False
            cond = rule["condition"].lower()

            if "any of" in cond:
                if len(matched_strings) > 0:
                    is_matched = True
            elif "and" in cond:
                required_count = len(rule["strings"])
                if len(matched_strings) >= required_count or len(matched_strings) >= 2:
                    is_matched = True
            elif "or" in cond:
                if len(matched_strings) > 0:
                    is_matched = True
            else:
                if len(matched_strings) > 0:
                    is_matched = True

            if is_matched:
                matched_rules.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "description": rule["meta"]["description"],
                    "matched_strings": matched_strings,
                    "threat_level": rule["meta"]["threat_level"]
                })

        return {
            "matches": matched_rules,
            "match_count": len(matched_rules),
            "total_rules_scanned": len(self.rules)
        }
