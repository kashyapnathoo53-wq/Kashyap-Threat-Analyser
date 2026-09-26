# PASHA 2.0 — WINDOWS LOCAL AGENT SPECIFICATION

**Module:** `backend/agent`  
**Version:** 2.0.0  
**Target Platform:** Windows 10 / Windows 11  
**Execution Mode:** Strictly Read-Only  

---

## 1. Overview & Purpose

The **Pasha Local Agent** is a non-intrusive, read-only Windows host inspection module designed to automatically collect security-relevant telemetry across the operating system.

Instead of requiring users to manually identify and upload suspicious executables, the Local Agent inspects security-critical attack surfaces (active processes, startup persistence keys, services, scheduled tasks, network sockets, volatile drop folders, and browser footprints) and constructs an internally normalized **Security Snapshot**.

---

## 2. Directory Layout

The agent is organized as a modular package within `backend/agent/`:

```
backend/agent/
├── __init__.py                  # Package definition
├── main.py                      # CLI entrypoint, orchestration & Native Messaging host
│
├── collectors/                  # Individual read-only host collectors
│   ├── __init__.py
│   ├── processes.py             # Running processes (PID, PPID, CLI, user, integrity)
│   ├── persistence.py           # Registry RunKeys (HKLM/HKCU), Startup, Winlogon
│   ├── services.py              # Windows services configuration and ImagePaths
│   ├── scheduled_tasks.py       # Scheduled tasks (names, paths, actions, authors)
│   ├── network.py               # Active TCP/UDP connections & socket-to-PID mapping
│   ├── files.py                 # Security-relevant drop zones (Downloads, Temp, AppData)
│   └── browser.py               # Lightweight browser profile and extension auditing
│
├── models/
│   ├── __init__.py
│   └── snapshot.py              # Normalized Pydantic models for items and snapshots
│
├── security/
│   ├── __init__.py
│   └── suspicious_items.py      # Explainable heuristic rules for anomaly pre-flagging
│
├── storage/
│   ├── __init__.py
│   └── snapshot_store.py        # Local disk persistence and snapshot indexer
│
└── communication/
    ├── __init__.py
    └── protocol.py              # Standardized message schema & Native Messaging framing
```

---

## 3. Read-Only Safety Guarantees

In accordance with Pasha's core safety rules, the Local Agent is **strictly read-only**:

* **Zero Deletion:** Never deletes files, folders, or logs.
* **Zero Process Termination:** Does not kill, suspend, or terminate processes.
* **Zero Registry Mutation:** Opens registry keys exclusively with `winreg.KEY_READ`. Does not create, modify, or delete values.
* **Zero Persistence Modification:** Does not alter Startup folders, RunKeys, or Scheduled Tasks.
* **Zero Quarantine:** All defensive actions remain quarantined to analytical evaluation until explicit user confirmation in Milestone 10.

---

## 4. Collector Specifications

Each collector returns a tuple of `(List[Item], CollectorReport)`.

### 4.1 Process Collector (`processes.py`)
* **Collection Method:** Native Windows `Get-CimInstance Win32_Process` complemented by `tasklist /FO CSV /V` for user and session mapping.
* **Collected Attributes:**
  * `pid` (int): Process identifier.
  * `name` (str): Image filename (e.g. `explorer.exe`).
  * `ppid` (int): Parent process identifier.
  * `path` (str): Full filesystem path to the executable binary.
  * `cmdline` (str): Complete command-line string with invocation arguments.
  * `user` (str): Executing security principal (e.g. `NT AUTHORITY\SYSTEM` or domain user).
  * `integrity_level` (str): Token integrity rating (`SYSTEM`, `High`, `Medium`, `Low`).
* **Heuristics:** Flags executions from `Temp` or non-standard `AppData`, typosquatted system process names (e.g. `svch0st`), known attack binaries, and encoded command lines.

### 4.2 Persistence Collector (`persistence.py`)
* **Collection Method:** Direct `winreg` inspection across both 32-bit and 64-bit registry hives:
  * `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce`
  * `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce`
  * `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run` and `RunOnce`
  * `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` (`Shell`, `Userinit`)
* **Startup Directories:**
  * `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
  * `%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
* **Heuristics:** Flags persistence targets residing in Temp/AppData or invoking script engines (`wscript`, `powershell -enc`).

### 4.3 Services Collector (`services.py`)
* **Collection Method:** Direct enumeration of `HKLM\SYSTEM\CurrentControlSet\Services` via `winreg`.
* **Collected Attributes:** Service Name, Display Name, ImagePath (binary target), Start Mode (`Boot`, `System`, `Auto`, `Manual`, `Disabled`).
* **Heuristics:** Flags services executing from user-writable directories or triggering raw scripts.

### 4.4 Scheduled Tasks Collector (`scheduled_tasks.py`)
* **Collection Method:** Fast native `schtasks /query /FO CSV /V` with column mapping for Task Name, Path, Status, Action/Command, and Author.
* **Heuristics:** Flags non-Windows tasks pointing to user profiles, temporary directories, or executing obfuscated PowerShell routines.

### 4.5 Network Collector (`network.py`)
* **Collection Method:** Native `netstat -ano` capturing active TCP and UDP sockets mapped to their owning PIDs.
* **Correlation:** Joins with the collected process list to attach the owning `process_name`.
* **Heuristics:** Flags connections to known reverse shell/attack ports (`4444`, `1337`, `6667`, etc.) and direct foreign sockets maintained by command interpreters (`cmd.exe`, `powershell.exe`).

### 4.6 File Collector (`files.py`)
* **Targeted Scanning (No Full-Drive Crawling):** Focuses strictly on high-probability malware drop zones:
  * `%USERPROFILE%\Downloads`
  * `%TEMP%` and `%TMP%` (User Temp)
  * `C:\Windows\Temp` (System Temp)
  * `%LOCALAPPDATA%` and `%LOCALAPPDATA%\Programs`
  * Executable paths referenced by currently running processes.
* **Suspicious File Types:** `.exe`, `.dll`, `.sys`, `.scr`, `.pif`, `.ps1`, `.vbs`, `.bat`, `.cmd`, `.js`, `.hta`, `.docm`, `.xlsm`, `.iso`.
* **Hashing:** Calculates SHA-256 for binaries and scripts under 25MB using streaming 64KB chunks.
* **Heuristics:** Flags masquerading double extensions (e.g. `Invoice.pdf.exe`) and volatile scripts.

### 4.7 Browser Collector (`browser.py`)
* **Collection Method:** Lightweight filesystem presence checks and default browser protocol association via `HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice`.
* **Supported Browsers:** Google Chrome, Microsoft Edge, Brave, Mozilla Firefox.
* **Non-Intrusive:** Does not lock SQLite database files or disrupt running browser sessions.

---

## 5. Failure Isolation & Error Handling

A failure in any individual collector will **never crash the scan**:

```python
try:
    items = run_collector()
    status = "SUCCESS"
except Exception as e:
    status = "PARTIAL" if items else "ERROR"
    error_msg = str(e)
```

Each collector reports its status (`SUCCESS`, `PARTIAL`, `ERROR`), item count, and duration in milliseconds in `CollectorReport`.

---

## 6. Snapshot Persistence (`SnapshotStore`)

Snapshots are automatically saved as formatted JSON documents in:
```
backend/agent/data/snapshots/snapshot_{snapshot_id}.json
```

Each snapshot includes:
* `snapshot_id`: `snap_YYYYMMDD_HHMMSS_<hex>`
* `schema_version`: `2.0.0`
* `timestamp`: UTC ISO 8601 string
* `system_info`: Hostname, OS, architecture, user, agent version
* `summary`: Item counts and suspicious candidate totals
* `collector_reports`: Duration and health per collector
* Detailed arrays for processes, persistence, services, tasks, network, files, and browsers.

---

## 7. How to Run and Test the Agent Locally

### Run Local Scan from CLI
```powershell
cd backend
python -m agent.main
```

### Run Scan with Full JSON Output
```powershell
python -m agent.main --json
```

### Run Dedicated Unit Tests
```powershell
python test_agent.py
```

### Run Unified Test Suite
```powershell
python run_tests.py
```
