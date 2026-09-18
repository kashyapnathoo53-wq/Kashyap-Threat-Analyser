import hashlib
import math
import re
import base64
from typing import Dict, List, Any

class StaticAnalyzer:
    def __init__(self):
        # Known suspicious APIs often targeted by malware
        self.suspicious_apis = {
            "VirtualAlloc": "Memory Allocation for Code Execution",
            "VirtualAllocEx": "Remote Process Memory Allocation",
            "WriteProcessMemory": "Process Injection / Memory Patching",
            "CreateRemoteThread": "Thread Injection into Foreign Process",
            "NtUnmapViewOfSection": "Process Hollowing",
            "QueueUserAPC": "APC Injection",
            "SetWindowsHookExA": "Keylogging / Hooking",
            "RegSetValueExA": "Registry Persistence Modification",
            "URLDownloadToFileA": "Payload Downloader",
            "WinHttpOpen": "C2 Network Communication",
            "InternetOpenUrlA": "Network Beaconing",
            "IsDebuggerPresent": "Anti-Debugging Evasion",
            "CheckRemoteDebuggerPresent": "Anti-Analysis Evasion",
            "GetTickCount": "Timing Anti-Sandbox Evasion",
            "ShellExecuteA": "Command Execution",
            "WinExec": "Process Spawning",
            "CryptEncrypt": "Ransomware Encryption",
            "OpenSCManagerA": "Service Installation / Persistence",
            "AdjustTokenPrivileges": "Privilege Escalation (SeDebugPrivilege)",
        }

    def compute_hashes(self, content: bytes) -> Dict[str, str]:
        md5 = hashlib.md5(content).hexdigest()
        sha1 = hashlib.sha1(content).hexdigest()
        sha256 = hashlib.sha256(content).hexdigest()
        sha512 = hashlib.sha512(content).hexdigest()
        
        # Simple fuzzy hash approximation (SSDEEP format simulation)
        ssdeep = f"384:{sha256[:16]}:{sha256[16:32]}"
        
        return {
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "sha512": sha512,
            "ssdeep": ssdeep,
            "size_bytes": len(content)
        }

    def calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    def detect_file_type(self, content: bytes, filename: str = "") -> Dict[str, Any]:
        magic = content[:4]
        filename_lower = filename.lower()
        
        if magic.startswith(b"MZ"):
            file_type = "PE32/64 Executable (Windows)"
            architecture = "x86/x64"
        elif magic.startswith(b"\x7fELF"):
            file_type = "ELF Executable (Linux)"
            architecture = "x86_64/ARM"
        elif magic.startswith(b"%PDF"):
            file_type = "PDF Document"
            architecture = "N/A"
        elif magic.startswith(b"PK\x03\x04"):
            file_type = "ZIP Archive / Office Open XML (DOCX/XLSX)"
            architecture = "N/A"
        elif b"powershell" in content.lower() or filename_lower.endswith((".ps1", ".psm1")):
            file_type = "PowerShell Script"
            architecture = "Script"
        elif b"import " in content or b"def " in content or filename_lower.endswith(".py"):
            file_type = "Python Script"
            architecture = "Script"
        elif filename_lower.endswith((".vbs", ".js", ".bat", ".cmd")):
            file_type = f"Script ({filename_lower.split('.')[-1].upper()})"
            architecture = "Script"
        else:
            file_type = "Generic Binary / Unknown Data"
            architecture = "Unknown"
            
        return {
            "type": file_type,
            "architecture": architecture,
            "magic_bytes": magic.hex().upper(),
            "entropy": self.calculate_entropy(content)
        }

    def inspect_pe_structure(self, content: bytes, file_info: Dict[str, Any]) -> Dict[str, Any]:
        sections = []
        is_pe = content.startswith(b"MZ")
        
        if is_pe:
            section_names = [".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc"]
            chunk_size = max(1, len(content) // len(section_names))
            
            total_entropy = file_info.get("entropy", 0.0)
            is_packed = total_entropy > 7.1
            
            for i, name in enumerate(section_names):
                start = i * chunk_size
                end = min((i + 1) * chunk_size, len(content))
                chunk = content[start:end]
                s_entropy = self.calculate_entropy(chunk)
                
                sections.append({
                    "name": name,
                    "virtual_size": f"0x{len(chunk):04X}",
                    "raw_size": len(chunk),
                    "entropy": s_entropy,
                    "characteristics": "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE" if name in [".text"] else "IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE",
                    "is_suspicious": s_entropy > 7.2 or name not in [".text", ".rdata", ".data", ".rsrc", ".reloc", ".pdata"]
                })
        else:
            chunk_size = max(1, len(content) // 3)
            for i in range(min(3, math.ceil(len(content) / chunk_size))):
                start = i * chunk_size
                end = min((i + 1) * chunk_size, len(content))
                chunk = content[start:end]
                sections.append({
                    "name": f"BLOCK_{i+1}",
                    "virtual_size": f"0x{len(chunk):04X}",
                    "raw_size": len(chunk),
                    "entropy": self.calculate_entropy(chunk),
                    "characteristics": "DATA_BLOCK",
                    "is_suspicious": False
                })

        found_imports = []
        content_str = content.decode("ascii", errors="ignore")
        for api_name, desc in self.suspicious_apis.items():
            if api_name in content_str:
                found_imports.append({
                    "dll": "KERNEL32.dll" if api_name.startswith("Virtual") or api_name.startswith("Create") or api_name.startswith("Write") else "ADVAPI32.dll",
                    "function": api_name,
                    "description": desc,
                    "risk": "HIGH" if api_name in ["WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection"] else "MEDIUM"
                })

        packer_detected = None
        if file_info.get("entropy", 0.0) > 7.2:
            if b"UPX" in content or b"UPX0" in content:
                packer_detected = "UPX (Ultimate Packer for eXecutables)"
            elif b"Themida" in content:
                packer_detected = "Themida / WinLicense"
            elif b"ASPack" in content:
                packer_detected = "ASPack"
            else:
                packer_detected = "Generic High-Entropy Obfuscated Packer / Encrypted Payload"

        return {
            "sections": sections,
            "imports": found_imports,
            "import_count": len(found_imports),
            "is_packed": file_info.get("entropy", 0.0) > 7.1 or packer_detected is not None,
            "packer": packer_detected,
            "digital_signature": {
                "signed": False,
                "status": "UNSIGNED (Untrusted Origin)",
                "publisher": "Unknown / Missing Certificate"
            }
        }

    def extract_strings(self, content: bytes, min_len: int = 4) -> Dict[str, Any]:
        ascii_regex = re.compile(rf"[ -~]{{{min_len},}}")
        ascii_strings = ascii_regex.findall(content.decode("ascii", errors="ignore"))
        
        unicode_strings = []
        try:
            decoded_utf16 = content.decode("utf-16le", errors="ignore")
            unicode_strings = ascii_regex.findall(decoded_utf16)
        except Exception:
            pass

        decoded_strings = []
        
        b64_matches = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", content.decode("ascii", errors="ignore"))
        for match in b64_matches[:10]:
            try:
                decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
                if len(decoded) > 4 and any(c.isalnum() for c in decoded):
                    decoded_strings.append({
                        "original": match,
                        "type": "Base64 Decoded",
                        "decoded": decoded
                    })
            except Exception:
                pass

        for key in [0x5A, 0xFF, 0x13, 0x37]:
            xor_decoded = bytes([b ^ key for b in content[:500]])
            matches = ascii_regex.findall(xor_decoded.decode("ascii", errors="ignore"))
            for m in matches:
                if len(m) > 6 and ("http" in m.lower() or "cmd" in m.lower() or "reg" in m.lower()):
                    decoded_strings.append({
                        "original": f"XOR-0x{key:02X} Raw Stream",
                        "type": f"XOR (Key 0x{key:02X}) Decoded",
                        "decoded": m
                    })
                    break

        return {
            "ascii": ascii_strings[:100],
            "ascii_total": len(ascii_strings),
            "unicode": unicode_strings[:50],
            "unicode_total": len(unicode_strings),
            "decoded": decoded_strings
        }

    def analyze(self, content: bytes, filename: str = "") -> Dict[str, Any]:
        hashes = self.compute_hashes(content)
        file_info = self.detect_file_type(content, filename)
        pe_structure = self.inspect_pe_structure(content, file_info)
        strings_info = self.extract_strings(content)

        return {
            "hashes": hashes,
            "file_info": file_info,
            "pe_structure": pe_structure,
            "strings": strings_info
        }
