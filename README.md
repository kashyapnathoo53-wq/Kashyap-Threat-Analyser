# Kashyap Threat Analyser 🛡️

**Kashyap Threat Analyser** is an automated platform for static and behavioral malware analysis with multi-factor threat risk scoring (0-100), automated IOC extraction, interactive MITRE ATT&CK Matrix (v14+) mapping, YARA signature rule workbench, process execution sandbox emulation, and executive report exports (PDF, HTML, STIX 2.1, MISP, Markdown).

---

## 🚀 Key Features

- **Static Analysis Engine**:
  - Cryptographic Hashes (MD5, SHA1, SHA256, SHA512, SSDEEP fuzzy hash estimation)
  - PE/ELF/Script binary structural inspection & architecture identification
  - Section entropy calculation to detect packed/obfuscated binaries (UPX, Themida, ASPack)
  - Suspicious imported Windows API detection (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `CryptEncrypt`)
  - String extraction & auto-decoders (ASCII, UTF-16LE Unicode, Base64, XOR decoding)

- **Behavioral Sandbox Emulator**:
  - Interactive process execution hierarchy tree tracking PIDs, paths, CLI commands, and integrity levels
  - Real-time Win32 / NT Syscall API trace stream filterable by risk level
  - Filesystem & Registry mutation activity tracker (dropped binaries, ransom notes, startup RunKeys)
  - Dynamic C2 network socket capture (HTTP/S beaconing, DNS requests, destination IPs)

- **Multi-Factor Threat Risk Scoring (0–100)**:
  - Weighted category risk calculation (Static, YARA, Behavioral, IOC density, and MITRE TTPs)
  - Verdict tiers: `CLEAN`, `LOW RISK`, `SUSPICIOUS`, `MALICIOUS`, and `CRITICAL SEVERE`

- **MITRE ATT&CK Enterprise Matrix (v14+) Mapping**:
  - Automatic alignment of detected behaviors across all 12 core tactics
  - Specific technique triggers (`T1059.001`, `T1055.001`, `T1490`, `T1547.001`, `T1071.001`) with runtime evidence
  - One-click export for MITRE ATT&CK Navigator JSON layers

- **Automated IOC Extraction**:
  - Automatically identifies IPv4, URLs, FQDNs, Hashes, Registry Keys, File Paths, and Crypto Wallets (BTC, ETH)
  - One-click export to STIX 2.1 JSON, MISP JSON, and CSV format

- **YARA Signature Workbench**:
  - Pre-loaded detection rules (Ransomware, Infostealer, WebShell, Keylogger, Reverse Shell, Process Injection)
  - Live YARA rule editor, compiler, and validator

- **Automated Executive Reporting**:
  - Printable executive HTML reports, Markdown summaries, STIX 2.1 JSON bundles, and PDF export

---

## 🛠️ Tech Stack

- **Backend**: Python 3, FastAPI, Uvicorn, Pydantic, Python-Multipart
- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS, Recharts, Lucide Icons

---

## ⚡ Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/kashyapnathoo53-wq/Kashyap-Threat-Analyser.git
cd Kashyap-Threat-Analyser
```

### 2. Run Backend
```bash
cd backend
pip install -r requirements.txt
python main.py
```
*Backend runs on `http://localhost:8000` (API Docs at `http://localhost:8000/docs`).*

### 3. Run Frontend
```bash
cd ../frontend
npm install
npm run dev
```
*Frontend UI opens on `http://localhost:3000`.*

---

## 🧪 Running Tests
```bash
cd backend
python run_tests.py
```

---

## 📄 License
MIT License
