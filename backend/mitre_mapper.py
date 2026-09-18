from typing import Dict, List, Any

# Standard 12 MITRE ATT&CK Tactics definition
ATTACK_TACTICS = [
    {"id": "TA0001", "name": "Initial Access"},
    {"id": "TA0002", "name": "Execution"},
    {"id": "TA0003", "name": "Persistence"},
    {"id": "TA0004", "name": "Privilege Escalation"},
    {"id": "TA0005", "name": "Defense Evasion"},
    {"id": "TA0006", "name": "Credential Access"},
    {"id": "TA0007", "name": "Discovery"},
    {"id": "TA0008", "name": "Lateral Movement"},
    {"id": "TA0009", "name": "Collection"},
    {"id": "TA0011", "name": "Command and Control"},
    {"id": "TA0010", "name": "Exfiltration"},
    {"id": "TA0040", "name": "Impact"}
]

class MitreMapper:
    def __init__(self):
        pass

    def map_analysis(self, static_res: Dict[str, Any], yara_res: Dict[str, Any], behavioral_res: Dict[str, Any], ioc_res: Dict[str, Any]) -> Dict[str, Any]:
        mapped_techniques = []

        # 1. Execution: T1059 (Command and Scripting Interpreter)
        api_stream = behavioral_res.get("api_call_stream", [])
        for api in api_stream:
            if "powershell" in str(api.get("arguments", "")).lower() or "cmd.exe" in str(api.get("arguments", "")).lower():
                mapped_techniques.append({
                    "tactic_id": "TA0002",
                    "tactic_name": "Execution",
                    "technique_id": "T1059.001",
                    "technique_name": "PowerShell / Command Execution",
                    "evidence": f"Process invocation detected: {api.get('arguments')}",
                    "confidence": "HIGH"
                })
                break

        # 2. Defense Evasion & Process Injection: T1055 (Process Injection)
        for api in api_stream:
            if api.get("api") in ["WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx"]:
                mapped_techniques.append({
                    "tactic_id": "TA0005",
                    "tactic_name": "Defense Evasion",
                    "technique_id": "T1055.001",
                    "technique_name": "Dynamic-link Library Injection / Process Injection",
                    "evidence": f"API sequence {api.get('api')} executed on PID {api.get('pid')}",
                    "confidence": "CRITICAL"
                })
                break

        # 3. Persistence: T1547.001 (Registry Run Keys)
        reg_acts = behavioral_res.get("registry_activity", [])
        for reg in reg_acts:
            if "Run" in reg.get("key", "") or "Startup" in reg.get("key", ""):
                mapped_techniques.append({
                    "tactic_id": "TA0003",
                    "tactic_name": "Persistence",
                    "technique_id": "T1547.001",
                    "technique_name": "Registry Run Keys / Startup Folder",
                    "evidence": f"Registry persistence modified: {reg.get('key')} = {reg.get('value')}",
                    "confidence": "HIGH"
                })
                break

        # 4. Credential Access: T1003 (OS Credential Dumping / Browser Data)
        for api in api_stream:
            if api.get("api") in ["CryptUnprotectData"] or "Login Data" in str(api.get("arguments", "")):
                mapped_techniques.append({
                    "tactic_id": "TA0006",
                    "tactic_name": "Credential Access",
                    "technique_id": "T1555.003",
                    "technique_name": "Credentials from Web Browsers / DPAPI",
                    "evidence": f"Access to browser credential store via DPAPI {api.get('api')}",
                    "confidence": "CRITICAL"
                })
                break

        # 5. Discovery: T1083 (File and Directory Discovery) & T1057 (Process Discovery)
        for api in api_stream:
            if api.get("api") in ["IsDebuggerPresent", "GetTickCount"]:
                mapped_techniques.append({
                    "tactic_id": "TA0007",
                    "tactic_name": "Discovery",
                    "technique_id": "T1497.001",
                    "technique_name": "Virtualization/Sandbox Evasion (System Checks)",
                    "evidence": f"Sandbox timing/anti-debug API check {api.get('api')}",
                    "confidence": "MEDIUM"
                })
                break

        # 6. Command and Control: T1071.001 (Web Protocols / C2 Beaconing)
        net_acts = behavioral_res.get("network_activity", [])
        if len(net_acts) > 0:
            mapped_techniques.append({
                "tactic_id": "TA0011",
                "tactic_name": "Command and Control",
                "technique_id": "T1071.001",
                "technique_name": "Application Layer Protocol: Web Protocols (HTTP/HTTPS)",
                "evidence": f"Established C2 beacon stream to {net_acts[0].get('destination')} ({net_acts[0].get('domain')})",
                "confidence": "HIGH"
            })

        # 7. Impact: T1490 (Inhibit System Recovery) & T1486 (Data Encrypted for Impact)
        for yara_match in yara_res.get("matches", []):
            if "Ransomware" in yara_match.get("category", "") or "VSS" in yara_match.get("rule_name", ""):
                mapped_techniques.append({
                    "tactic_id": "TA0040",
                    "tactic_name": "Impact",
                    "technique_id": "T1490",
                    "technique_name": "Inhibit System Recovery (Volume Shadow Copy Deletion)",
                    "evidence": f"YARA detection hit: {yara_match.get('rule_name')} ({yara_match.get('description')})",
                    "confidence": "CRITICAL"
                })
                mapped_techniques.append({
                    "tactic_id": "TA0040",
                    "tactic_name": "Impact",
                    "technique_id": "T1486",
                    "technique_name": "Data Encrypted for Impact (Ransomware Payload)",
                    "evidence": "File system mass file extension modification and ransom note creation",
                    "confidence": "CRITICAL"
                })
                break

        # Deduplicate techniques by technique_id
        unique_techniques = []
        seen_tids = set()
        for tech in mapped_techniques:
            if tech["technique_id"] not in seen_tids:
                seen_tids.add(tech["technique_id"])
                unique_techniques.append(tech)

        # Build ATT&CK Navigator JSON compatibility schema
        navigator_layer = {
            "name": "Malware Analysis ATT&CK Coverage",
            "versions": {"attack": "14", "navigator": "4.8"},
            "domain": "enterprise-attack",
            "description": "Automatically generated MITRE ATT&CK Mapping Layer",
            "techniques": [
                {
                    "techniqueID": t["technique_id"],
                    "tactic": t["tactic_name"].lower().replace(" ", "-"),
                    "score": 100 if t["confidence"] == "CRITICAL" else 75 if t["confidence"] == "HIGH" else 50,
                    "comment": t["evidence"],
                    "enabled": True
                }
                for t in unique_techniques
            ]
        }

        return {
            "tactics": ATTACK_TACTICS,
            "mapped_techniques": unique_techniques,
            "total_mapped_techniques": len(unique_techniques),
            "navigator_layer": navigator_layer
        }
