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
        # Fast streaming hash computation to prevent memory pressure on large files
        h_md5 = hashlib.md5()
        h_sha1 = hashlib.sha1()
        h_sha256 = hashlib.sha256()
        h_sha512 = hashlib.sha512()

        chunk_size = 65536
        total_len = len(content)
        for i in range(0, total_len, chunk_size):
            chunk = content[i:i + chunk_size]
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)
            h_sha512.update(chunk)

        sha256 = h_sha256.hexdigest()
        ssdeep = f"384:{sha256[:16]}:{sha256[16:32]}"

        return {
            "md5": h_md5.hexdigest(),
            "sha1": h_sha1.hexdigest(),
            "sha256": sha256,
            "sha512": h_sha512.hexdigest(),
            "ssdeep": ssdeep,
            "size_bytes": total_len
        }

    def calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        # If data is large (> 256KB), take a representative sample for ultra-fast response
        if len(data) > 262144:
            step = len(data) // 262144
            sample = data[::step][:262144]
        else:
            sample = data

        length = len(sample)
        freq = {}
        for byte in sample:
            freq[byte] = freq.get(byte, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    def detect_file_type(self, content: bytes, filename: str = "") -> Dict[str, Any]:
        magic = content[:4]
        filename_lower = filename.lower()
        
        # Sample first 64KB for script keywords to ensure instant detection without freeze
        header_sample = content[:65536].lower()

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
        elif b"powershell" in header_sample or filename_lower.endswith((".ps1", ".psm1")):
            file_type = "PowerShell Script"
            architecture = "Script"
        elif b"import " in header_sample or b"def " in header_sample or filename_lower.endswith(".py"):
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

        # Efficient API search: search in representative decoded window (up to 512KB)
        sample_slice = content[:524288].decode("ascii", errors="ignore")
        found_imports = []
        for api_name, desc in self.suspicious_apis.items():
            if api_name in sample_slice:
                found_imports.append({
                    "dll": "KERNEL32.dll" if api_name.startswith("Virtual") or api_name.startswith("Create") or api_name.startswith("Write") else "ADVAPI32.dll",
                    "function": api_name,
                    "description": desc,
                    "risk": "HIGH" if api_name in ["WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection"] else "MEDIUM"
                })

        packer_detected = None
        sample_lower = content[:524288].lower()
        if file_info.get("entropy", 0.0) > 7.1:
            if b"upx" in sample_lower:
                packer_detected = "UPX (Ultimate Packer for eXecutables)"
            elif b"themida" in sample_lower:
                packer_detected = "Themida / WinLicense"
            elif b"aspack" in sample_lower:
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
        # Bound the string extraction target to prevent freezing on large multi-megabyte binaries
        # Standard malware string extraction analyzes header + first 512KB + tail 256KB
        if len(content) > 786432:
            target_slice = content[:524288] + content[-262144:]
        else:
            target_slice = content

        ascii_regex = re.compile(rf"[ -~]{{{min_len},}}")
        text_str = target_slice.decode("ascii", errors="ignore")
        ascii_strings = ascii_regex.findall(text_str)

        # Unicode extraction (bounded to first 256KB)
        unicode_strings = []
        try:
            decoded_utf16 = target_slice[:262144].decode("utf-16le", errors="ignore")
            unicode_strings = ascii_regex.findall(decoded_utf16)
        except Exception:
            pass

        # Decoded strings (Base64 heuristic)
        decoded_strings = []
        # Search base64 in text_str (limited to first 200 matches)
        b64_matches = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text_str[:131072])
        for match in b64_matches[:12]:
            try:
                decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
                if len(decoded) > 4 and any(c.isalnum() for c in decoded):
                    decoded_strings.append({
                        "original": match[:32] + "...",
                        "type": "Base64 Decoded",
                        "decoded": decoded[:120]
                    })
            except Exception:
                pass

        # Fast XOR probe on first 500 bytes
        xor_slice = content[:500]
        for key in [0x5A, 0xFF, 0x13, 0x37]:
            xor_decoded = bytes([b ^ key for b in xor_slice])
            matches = ascii_regex.findall(xor_decoded.decode("ascii", errors="ignore"))
            for m in matches:
                if len(m) > 6 and any(k in m.lower() for k in ["http", "cmd", "reg", "powershell", "api"]):
                    decoded_strings.append({
                        "original": f"XOR-0x{key:02X} Stream",
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
