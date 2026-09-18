import time
import random
from typing import Dict, List, Any

class BehavioralEmulator:
    def __init__(self):
        pass

    def emulate_execution(self, content: bytes, file_info: Dict[str, Any], static_results: Dict[str, Any]) -> Dict[str, Any]:
        content_str = content.decode("ascii", errors="ignore").lower()
        filename = file_info.get("filename", "sample.exe")
        
        # Determine malware archetype based on contents or fallback heuristics
        is_ransomware = "vssadmin" in content_str or "encrypt" in content_str or "shadow" in content_str or "lockbit" in content_str or "wannacry" in content_str
        is_infostealer = "login data" in content_str or "chrome" in content_str or "sqlite" in content_str or "emotet" in content_str
        is_webshell = "eval" in content_str or "shell_exec" in content_str or "passthru" in content_str
        is_cobalt_strike = "virtualalloc" in content_str and "createremotethread" in content_str
        
        # Build Process Tree Nodes
        p_root = {"pid": 4096, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe", "cmd": "C:\\Windows\\explorer.exe", "integrity": "Medium"}
        p_malware = {"pid": 6120, "name": filename if filename.endswith(".exe") else "sample.exe", "path": f"C:\\Users\\Victim\\AppData\\Local\\Temp\\{filename}", "cmd": f"\"C:\\Users\\Victim\\AppData\\Local\\Temp\\{filename}\" /start", "integrity": "Medium"}
        
        children = []
        api_logs = []
        fs_activity = []
        reg_activity = []
        net_activity = []

        base_time = 1718000000.0

        # Generic startup API calls
        api_logs.append({
            "timestamp": base_time + 0.1,
            "pid": 6120,
            "process": p_malware["name"],
            "api": "IsDebuggerPresent",
            "category": "Anti-Analysis",
            "arguments": "None",
            "return_val": "0 (False)",
            "risk": "LOW"
        })

        api_logs.append({
            "timestamp": base_time + 0.3,
            "pid": 6120,
            "process": p_malware["name"],
            "api": "GetTickCount",
            "category": "Timing Evasion",
            "arguments": "None",
            "return_val": "1428570",
            "risk": "LOW"
        })

        if is_ransomware:
            p_cmd = {"pid": 7210, "name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe", "cmd": "cmd.exe /c vssadmin.exe delete shadows /all /quiet", "integrity": "High"}
            p_vss = {"pid": 8044, "name": "vssadmin.exe", "path": "C:\\Windows\\System32\\vssadmin.exe", "cmd": "vssadmin.exe delete shadows /all /quiet", "integrity": "High"}
            
            p_malware["children"] = [
                {**p_cmd, "children": [p_vss]}
            ]

            api_logs.append({
                "timestamp": base_time + 1.2,
                "pid": 6120,
                "process": p_malware["name"],
                "api": "CreateProcessW",
                "category": "Process Creation",
                "arguments": "lpCommandLine='cmd.exe /c vssadmin.exe delete shadows /all /quiet'",
                "return_val": "SUCCESS (PID 7210)",
                "risk": "CRITICAL"
            })

            api_logs.append({
                "timestamp": base_time + 2.5,
                "pid": 6120,
                "process": p_malware["name"],
                "api": "CryptEncrypt",
                "category": "Encryption",
                "arguments": "hKey=0x004FA21, pbData=[User Files Buffer]",
                "return_val": "SUCCESS",
                "risk": "CRITICAL"
            })

            fs_activity.extend([
                {"action": "DROP_FILE", "path": "C:\\Users\\Victim\\Desktop\\READ_ME_FOR_DECRYPT.txt", "size": "4.2 KB"},
                {"action": "RENAME_ENCRYPT", "path": "C:\\Users\\Victim\\Documents\\Financial_Q3.xlsx.lockbit", "size": "1.4 MB"},
                {"action": "RENAME_ENCRYPT", "path": "C:\\Users\\Victim\\Pictures\\Family.png.lockbit", "size": "3.8 MB"}
            ])

            reg_activity.append({
                "action": "SET_VALUE",
                "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\RansomwareRestore",
                "value": "C:\\Users\\Victim\\AppData\\Local\\Temp\\sample.exe"
            })

            net_activity.append({
                "proto": "HTTPS",
                "destination": "185.220.101.4:443",
                "domain": "onion-gateway-tor.cc",
                "type": "C2 Communication / Ransom Key Exfiltration",
                "bytes_sent": 8420
            })

        elif is_infostealer:
            p_ps = {"pid": 6900, "name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "cmd": "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Victim\\AppData\\Local\\Temp\\steal.ps1", "integrity": "Medium"}
            p_malware["children"] = [p_ps]

            api_logs.append({
                "timestamp": base_time + 0.8,
                "pid": 6120,
                "process": p_malware["name"],
                "api": "CreateFileW",
                "category": "File Access",
                "arguments": "lpFileName='C:\\Users\\Victim\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data'",
                "return_val": "HANDLE (0x0000014C)",
                "risk": "HIGH"
            })

            api_logs.append({
                "timestamp": base_time + 1.1,
                "pid": 6120,
                "process": p_malware["name"],
                "api": "CryptUnprotectData",
                "category": "Credential Access",
                "arguments": "pDataIn=[Encrypted Browser Blob], pDataOut=[Plaintext Passwords]",
                "return_val": "SUCCESS",
                "risk": "CRITICAL"
            })

            fs_activity.extend([
                {"action": "READ_FILE", "path": "C:\\Users\\Victim\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", "size": "512 KB"},
                {"action": "CREATE_TEMP", "path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\passwords_stolen.zip", "size": "48 KB"}
            ])

            net_activity.append({
                "proto": "HTTP",
                "destination": "194.165.16.42:8080",
                "domain": "dropzone-exfil.xyz",
                "type": "Data Exfiltration (HTTP POST)",
                "bytes_sent": 49200
            })

        elif is_cobalt_strike:
            p_svchost = {"pid": 1120, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe", "cmd": "svchost.exe -k netsvcs", "integrity": "SYSTEM"}
            p_malware["children"] = [{"pid": 6121, "name": "target_process.exe", "path": "C:\\Windows\\System32\\notepad.exe", "cmd": "notepad.exe", "integrity": "Medium"}]

            api_logs.append({
                "timestamp": base_time + 0.5,
                "pid": 6120,
                "process": p_malware["name"],
                "api": "OpenProcess",
                "category": "Process Manipulation",
                "arguments": "dwDesiredAccess=PROCESS_ALL_ACCESS, dwProcessId=1120",
                "return_val": "HANDLE (0x00000210)",
                "risk": "HIGH"
            })

            api_logs.append({
                "timestamp": base_time + 0.9,
                "pid": 6120,
                "process": p_malware["name"],
                "api": "VirtualAllocEx",
                "category": "Memory Allocation",
                "arguments": "hProcess=0x0210, flProtect=PAGE_EXECUTE_READWRITE",
                "return_val": "0x007F0000",
                "risk": "HIGH"
            })

            api_logs.append({
                "timestamp": base_time + 1.4,
                "pid": 6120,
                "process": p_malware["name"],
                "api": "WriteProcessMemory",
                "category": "Memory Injection",
                "arguments": "hProcess=0x0210, lpBaseAddress=0x007F0000, lpBuffer=[Shellcode Blob]",
                "return_val": "SUCCESS (Write 4096 bytes)",
                "risk": "CRITICAL"
            })

            api_logs.append({
                "timestamp": base_time + 1.7,
                "pid": 6120,
                "process": p_malware["name"],
                "api": "CreateRemoteThread",
                "category": "Process Injection",
                "arguments": "hProcess=0x0210, lpStartAddress=0x007F0000",
                "return_val": "THREAD (0x000003E4)",
                "risk": "CRITICAL"
            })

            net_activity.append({
                "proto": "HTTPS",
                "destination": "45.142.214.18:443",
                "domain": "cdn-cloud-update.net",
                "type": "Cobalt Strike Beacon HTTP/S Loop",
                "bytes_sent": 1240
            })

        else:
            # Default suspicious behavior simulation
            p_malware["children"] = []
            api_logs.append({
                "timestamp": base_time + 0.4,
                "pid": 6120,
                "process": p_malware["name"],
                "api": "RegSetValueExW",
                "category": "Registry Modification",
                "arguments": "Key='HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', Value='Updater'",
                "return_val": "ERROR_SUCCESS",
                "risk": "HIGH"
            })
            
            api_logs.append({
                "timestamp": base_time + 1.0,
                "pid": 6120,
                "process": p_malware["name"],
                "api": "URLDownloadToFileW",
                "category": "Network Download",
                "arguments": "szURL='http://malicious-stage.com/payload.bin', szFileName='C:\\Users\\Victim\\AppData\\Local\\Temp\\stage2.exe'",
                "return_val": "S_OK",
                "risk": "HIGH"
            })

            fs_activity.append({"action": "CREATE_TEMP", "path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\stage2.exe", "size": "256 KB"})
            reg_activity.append({"action": "SET_VALUE", "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", "value": "C:\\Users\\Victim\\AppData\\Local\\Temp\\stage2.exe"})
            net_activity.append({"proto": "HTTP", "destination": "185.190.140.88:80", "domain": "malicious-stage.com", "type": "Payload Downloader", "bytes_sent": 512})

        # Wrap process root
        p_root["children"] = [p_malware]

        return {
            "process_tree": p_root,
            "api_call_stream": api_logs,
            "filesystem_activity": fs_activity,
            "registry_activity": reg_activity,
            "network_activity": net_activity,
            "total_api_calls": len(api_logs),
            "execution_time_seconds": 3.5
        }
