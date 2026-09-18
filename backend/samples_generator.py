from typing import Dict, List, Any

PRESET_SAMPLES = [
    {
        "id": "sample_wannacry",
        "name": "WannaCry_Ransomware.exe",
        "type": "PE32 Executable (Ransomware)",
        "description": "Simulated WannaCry Ransomware payload executing shadow copy deletion, file encryption, and C2 communication.",
        "content_bytes": b"MZ\x90\0\x03\0\0\0vssadmin.exe delete shadows /all /quiet bcdedit /set {default} recoveryenabled No CryptEncrypt VirtualAllocEx WriteProcessMemory CreateRemoteThread 185.220.101.4 C:\\Users\\Victim\\Desktop\\READ_ME_FOR_DECRYPT.txt UPX0 UPX1"
    },
    {
        "id": "sample_emotet",
        "name": "Emotet_Infostealer.exe",
        "type": "PE32 Executable (Trojan / Stealer)",
        "description": "Emotet Trojan dropper harvesting Chrome/Firefox passwords, DPAPI secrets, and exfiltrating over HTTP POST.",
        "content_bytes": b"MZ\x90\0\x03\0\0\0Login Data CryptUnprotectData powershell.exe -ExecutionPolicy Bypass -File steal.ps1 dropzone-exfil.xyz 194.165.16.42 SELECT origin_url, username_value, password_value FROM logins"
    },
    {
        "id": "sample_cobaltstrike",
        "name": "CobaltStrike_Beacon.dll",
        "type": "PE32 DLL (Command & Control)",
        "description": "Cobalt Strike malleable C2 beacon injecting shellcode into remote processes.",
        "content_bytes": b"MZ\x90\0\x03\0\0\0VirtualAllocEx WriteProcessMemory CreateRemoteThread NtUnmapViewOfSection 45.142.214.18 cdn-cloud-update.net svchost.exe IsDebuggerPresent GetTickCount"
    },
    {
        "id": "sample_webshell",
        "name": "c99_webshell.php",
        "type": "PHP WebShell Script",
        "description": "Obfuscated PHP WebShell providing backdoor remote administrative command execution.",
        "content_bytes": b"<?php eval(base64_decode('c3lzdGVtKCRfUkVRVUVTVFsnY21kJ10pOw==')); shell_exec($_POST['cmd']); passthru($_GET['exec']); system($_REQUEST['c']); ?>"
    },
    {
        "id": "sample_benign_calc",
        "name": "Calculator_Utility.exe",
        "type": "PE32 Executable (Benign)",
        "description": "Clean standard Windows Calculator system utility binary.",
        "content_bytes": b"MZ\x90\0\x03\0\0\0Microsoft Windows Calculator System Utility. GetModuleHandleA CreateWindowExW DispatchMessageW ExitProcess."
    }
]

def get_preset_samples() -> List[Dict[str, Any]]:
    return [
        {
            "id": s["id"],
            "name": s["name"],
            "type": s["type"],
            "description": s["description"]
        }
        for s in PRESET_SAMPLES
    ]

def get_preset_sample_by_id(sample_id: str) -> Dict[str, Any]:
    for s in PRESET_SAMPLES:
        if s["id"] == sample_id:
            return s
    return PRESET_SAMPLES[0]
