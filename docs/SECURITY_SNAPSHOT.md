# PASHA 2.0 — SECURITY SNAPSHOT SPECIFICATION & PERSISTENCE

**Document Version:** 2.0.0  
**Status:** Implemented & Verified (Milestone 2 Completed)  
**Schema Version:** 2.0.0  
**Target Platform:** Windows 10/11 (Local-First Architecture)  

---

## 1. Overview & Architectural Role

In Pasha 2.0, a **Security Snapshot** is an immutable, point-in-time forensic capture of a Windows host's security-critical attack surfaces.

Rather than running uncontrolled whole-disk crawls, Pasha's Local Agent queries targeted telemetry sources:
* Running user and system processes
* Persistent startup mechanisms (Registry Run/RunOnce, Startup folders, Winlogon)
* Windows Services configurations and binary paths
* Active scheduled tasks
* Live TCP/UDP network connections mapped to process owners
* Volatile and high-risk file directories (`Downloads`, `AppData`, `Temp`, Startup)
* Installed browser footprints and profiles

Snapshots serve as the foundational dataset for all downstream analytical layers in Pasha 2.0:
```
┌────────────────────────────────────────────────────────┐
│                   LOCAL AGENT SCAN                     │
│    (Processes, Persistence, Services, Tasks, Net, Files)│
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│           NORMALIZED SECURITY SNAPSHOT (v2.0.0)        │
│ • Canonical versioned JSON document                    │
│ • Local disk persistence (`backend/agent/data/`)       │
│ • Pre-screened unified `suspicious_items` list         │
└──────────────┬───────────────────────────┬─────────────┘
               │                           │
               ▼                           ▼
┌──────────────────────────────┐ ┌──────────────────────────────┐
│    SECURITY DIFF ENGINE      │ │ AUTOMATIC CANDIDATE DETECTOR │
│ ("What changed on my PC?")   │ │ (Prioritizes suspect binaries│
│ Milestone 3                  │ │  for Static/YARA/Sandbox)    │
│                              │ │ Milestone 4 & 5              │
└──────────────────────────────┘ └──────────────────────────────┘
```

---

## 2. Canonical JSON Schema (v2.0.0)

Every snapshot is stored as a versioned, indented JSON file: `snapshot_{snapshot_id}.json`.

### 2.1 Top-Level Fields

| Field Name | Type | Description |
|---|---|---|
| `snapshot_id` | `string` | Unique snapshot identifier (`snap_YYYYMMDD_HHMMSS_<hex>`) |
| `schema_version` | `string` | Normalized schema version (`"2.0.0"`) |
| `timestamp` | `string` | ISO 8601 UTC timestamp of scan initiation |
| `host_id` | `string` | Persistent machine identifier (`MachineGuid` or hardware hash) |
| `os_version` | `string` | Human-readable OS version string |
| `system_info` | `object` | Comprehensive host metadata (hostname, user, python, arch) |
| `summary` | `object` | High-level counts of scanned and suspicious items |
| `snapshot_metadata`| `object` | Execution duration, item counts, agent version, collector statuses |
| `collectors_executed`| `object` | Map of collector names to execution status and duration reports |
| `processes` | `array` | List of normalized running process items |
| `persistence_items` | `array` | List of normalized persistence mechanisms |
| `services` | `array` | List of normalized Windows services |
| `scheduled_tasks` | `array` | List of normalized scheduled tasks |
| `network_connections`| `array`| List of active TCP/UDP sockets mapped to PIDs |
| `scanned_files` | `array` | List of volatile/security-relevant file metadata and hashes |
| `browser_info` | `array` | List of installed browser footprints |
| `suspicious_items` | `array` | Pre-screened consolidated anomalous items across all collectors |

### 2.2 Backward Compatibility & Aliases
To ensure seamless interoperability between legacy components and newer normalized consumers, Pydantic field aliases and accessor properties are configured:
* `persistence` ↔ `persistence_items`
* `network` ↔ `network_connections`
* `files` ↔ `scanned_files`
* `browser` ↔ `browser_info`
* `collector_reports` ↔ `collectors_executed`

REST API responses serialize both canonical keys and alias helper keys so all consumers function without migration friction.

---

## 3. Data Models

### 3.1 `SuspiciousSummaryItem`
Unified pre-screened anomaly item surfaced directly in `snapshot.suspicious_items`:
```json
{
  "category": "process",
  "name": "powershell.exe",
  "target": "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA...",
  "reasons": [
    "Encoded PowerShell invocation (-enc/-encodedcommand)",
    "Obfuscated script block execution"
  ],
  "severity": "HIGH",
  "details": {
    "pid": 4812,
    "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "user": "DOMAIN\\analyst"
  }
}
```

### 3.2 `ProcessItem`
```json
{
  "pid": 3216,
  "name": "chrome.exe",
  "ppid": 1048,
  "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "cmdline": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=renderer",
  "user": "quadr",
  "integrity_level": "Medium",
  "creation_time": "2026-09-25 18:20:11",
  "is_suspicious": false,
  "suspicious_reasons": []
}
```

### 3.3 `PersistenceItem`
```json
{
  "name": "OneDrive",
  "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "command": "\"C:\\Users\\quadr\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background",
  "file_path": "C:\\Users\\quadr\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
  "type": "Registry RunKey",
  "is_suspicious": false,
  "suspicious_reasons": []
}
```

### 3.4 `NetworkConnectionItem`
```json
{
  "proto": "TCP",
  "local_addr": "192.168.1.100",
  "local_port": 54312,
  "remote_addr": "142.250.190.46",
  "remote_port": 443,
  "state": "ESTABLISHED",
  "pid": 3216,
  "process_name": "chrome.exe",
  "is_suspicious": false,
  "suspicious_reasons": []
}
```

### 3.5 `FileItem`
```json
{
  "path": "C:\\Users\\quadr\\Downloads\\Invoice.pdf.exe",
  "name": "Invoice.pdf.exe",
  "size_bytes": 142336,
  "category": "Downloads",
  "extension": ".exe",
  "created_time": "2026-09-25T12:44:10",
  "modified_time": "2026-09-25T12:44:10",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "is_suspicious": true,
  "suspicious_reasons": [
    "Executable disguised with double extension (.pdf.exe)"
  ]
}
```

---

## 4. Local Storage & Retention Architecture

### 4.1 Storage Directory
Snapshots are persisted locally under:
```
backend/
└── agent/
    └── data/
        └── snapshots/
            ├── snapshot_snap_20260925_130825_6d6dcc.json
            ├── snapshot_snap_20260925_130922_5fa4c4.json
            └── snapshot_snap_20260925_131407_dff57d.json
```
The storage directory is created automatically on startup and is kept within local repository data paths.

### 4.2 Retention Policy Engine (`SnapshotStore.prune_snapshots`)
To prevent unbounded disk consumption from repeated scheduled or automated scans, Pasha includes an automated two-stage retention policy:

1. **Age-Based Pruning (`max_age_days`):**
   * Any snapshot older than `max_age_days` (default 30 days) is evaluated and safely unlinked.
2. **Ceiling-Based Pruning (`max_snapshots`):**
   * If remaining snapshots exceed `max_snapshots` (default 30), the oldest snapshots are pruned first, ensuring the storage directory maintains a bounded footprint.
3. **Automatic Retention on Save:**
   * Calling `store.save_snapshot(snapshot, auto_prune=True)` automatically prunes excess snapshots upon write.

---

## 5. REST API Reference

All agent snapshot endpoints are integrated into Pasha's FastAPI backend (`http://localhost:8000`).

### 5.1 `GET /api/agent/status`
Returns agent operational readiness, unique machine ID, and storage statistics.

**Response:**
```json
{
  "status": "online",
  "agent_version": "2.0.0",
  "machine_id": "f8bd7f45-90ca-4b7d-96d8-d7100578d6ae",
  "storage": {
    "total_snapshots": 3,
    "storage_dir": "c:\\Users\\...\\backend\\agent\\data\\snapshots",
    "total_size_bytes": 2202854,
    "total_size_mb": 2.1,
    "latest_snapshot_id": "snap_20260925_131407_dff57d",
    "latest_timestamp": "2026-09-25T13:14:07.123456+00:00"
  }
}
```

---

### 5.2 `GET /api/agent/snapshots`
Lists all recorded snapshots in reverse chronological order (newest first). Supports pagination.

**Query Parameters:**
* `limit` (optional, default `50`): Maximum entries to return.
* `offset` (optional, default `0`): Pagination offset.

**Response:**
```json
{
  "total": 3,
  "limit": 50,
  "offset": 0,
  "snapshots": [
    {
      "snapshot_id": "snap_20260925_131407_dff57d",
      "schema_version": "2.0.0",
      "timestamp": "2026-09-25T13:14:07.123456+00:00",
      "host_id": "f8bd7f45-90ca-4b7d-96d8-d7100578d6ae",
      "hostname": "Z-zown",
      "os_version": "Windows 11 (10.0.26200)",
      "file_path": "c:\\Users\\...\\snapshot_snap_20260925_131407_dff57d.json",
      "file_size_bytes": 734850,
      "summary": {
        "total_processes": 318,
        "suspicious_processes": 0,
        "total_suspicious_items": 4,
        "scan_duration_ms": 8500.2
      },
      "total_suspicious_items": 4
    }
  ]
}
```

---

### 5.3 `GET /api/agent/snapshots/latest`
Retrieves the complete payload of the most recent security snapshot.

**Response (HTTP 200):**
Full `SecuritySnapshot` object with all normalized fields and convenience aliases. Returns `HTTP 404` if no snapshots exist.

---

### 5.4 `GET /api/agent/snapshots/{snapshot_id}`
Retrieves a specific security snapshot by ID or filename.

**Parameters:**
* `snapshot_id`: e.g. `snap_20260925_131407_dff57d`

**Response (HTTP 200):** Full `SecuritySnapshot` object. Returns `HTTP 404` if not found.

---

### 5.5 `POST /api/agent/scan`
Triggers an on-demand, non-intrusive security scan across all host collectors.

**Request Body (optional):**
```json
{
  "save_to_store": true,
  "max_snapshots": 50
}
```

**Response (HTTP 200):** The freshly generated `SecuritySnapshot`.

---

### 5.6 `DELETE /api/agent/snapshots/{snapshot_id}`
Safely deletes a specified snapshot file from disk.

**Response (HTTP 200):**
```json
{
  "status": "deleted",
  "snapshot_id": "snap_20260925_131407_dff57d"
}
```

---

### 5.7 `POST /api/agent/snapshots/prune`
Manually triggers retention policy enforcement.

**Request Body:**
```json
{
  "max_snapshots": 30,
  "max_age_days": 30
}
```

**Response (HTTP 200):**
```json
{
  "status": "success",
  "result": {
    "pruned_count": 2,
    "deleted_snapshots": [
      "snap_20260801_100000_123456",
      "snap_20260802_110000_654321"
    ],
    "remaining_count": 30
  }
}
```

---

## 6. Security, Privacy & Safety Guarantees

1. **Read-Only Invariant:**
   * The snapshot process strictly inspects system state. It does not terminate processes, alter registry entries, or delete files.
2. **Local-First Privacy:**
   * Snapshots are written strictly to the local host filesystem. No telemetry, hashes, command lines, or usernames are transmitted outside the local machine.
3. **No Whole-Disk Crawls:**
   * File collection is constrained to high-risk volatile zones (`Downloads`, `Temp`, `AppData`, `Startup`) and process-referenced binaries, completing scans in ~8–9 seconds with low CPU impact.
4. **Resilient Error Isolation:**
   * Each collector executes inside a defensive `try/except` boundary. If permission is denied for a specific registry key or process, a partial report is returned rather than terminating the overall snapshot.
