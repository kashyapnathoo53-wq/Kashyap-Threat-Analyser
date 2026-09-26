# PASHA 2.0 — SECURITY DIFF ENGINE SPECIFICATION

**Document Version:** 2.0.0  
**Status:** Implemented & Verified (Milestone 3 Completed)  
**Target Platform:** Windows 10/11 (Local-First Architecture)  

---

## 1. Overview & Objective

In threat hunting and host incident investigation, the most important question is:
> **"What changed on my computer between time $T_0$ and time $T_1$?"**

Traditional endpoint monitoring tools dump raw event logs containing thousands of noise events. Pasha 2.0's **Security Diff Engine** (`agent/security/diff.py`) performs structural, stateful comparisons between consecutive or arbitrary point-in-time snapshots to isolate the exact delta:

```
┌───────────────────────────┐      ┌───────────────────────────┐
│     BASE SNAPSHOT (T0)    │      │    TARGET SNAPSHOT (T1)   │
│   (e.g., Clean Baseline)  │      │  (e.g., Post-Infection)   │
└─────────────┬─────────────┘      └─────────────┬─────────────┘
              │                                  │
              └────────────────┬─────────────────┘
                               │
                               ▼
              ┌──────────────────────────────────┐
              │       SECURITY DIFF ENGINE       │
              │  • Identity Resolution           │
              │  • Added / Removed / Modified    │
              │  • Risk Significance Filtering   │
              └────────────────┬─────────────────┘
                               │
                               ▼
              ┌──────────────────────────────────┐
              │       SECURITY DIFF RESULT       │
              │  • Overall Verdict & Color       │
              │  • Surface Category Diffs        │
              │  • Priority Security Candidates  │
              └──────────────────────────────────┘
```

---

## 2. Structural Comparison Architecture

The engine computes deltas across all 7 monitored host surfaces:

### 2.1 Processes
* **Identity Resolution:** Composite key `(process_name.lower(), process_path.lower())`.
* **Added Processes:**
  * Flagged as **CRITICAL** if pre-screening heuristics detect ransomware commands (`vssadmin delete shadows`), credential dumping (`mimikatz`), or encoded PowerShell blocks.
  * Flagged as **HIGH** if executing from temporary directories (`AppData\Local\Temp`, `Windows\Temp`) or non-standard user profiles.
  * Flagged as **INFO** if standard system or known applications (`System32\svchost.exe`, `chrome.exe`).
* **Removed Processes:**
  * Categorized as **MEDIUM** if a previously flagged suspicious process terminated.
  * Categorized as **INFO** for benign terminations.

### 2.2 Persistence Mechanisms
* **Identity Resolution:** Composite key `(location.lower(), name.lower())` covering Registry Run/RunOnce, Startup folders, and Winlogon.
* **Added Persistence:**
  * Any new persistence item is inherently security-significant (**HIGH** by default).
  * If points to user `Temp` or executes script files (`.vbs`, `.ps1`, `.bat`), flagged as **CRITICAL**.
* **Modified Persistence:**
  * Existing key with command altered flagged as **CRITICAL** (e.g. hijacking existing entry).

### 2.3 Windows Services
* **Identity Resolution:** Case-insensitive service name (`service_name.lower()`).
* **Added Services:** New services flagged as **HIGH** or **CRITICAL** (if user-writable binary path).
* **Modified Services:**
  * Binary path modified: **CRITICAL** (Service hijacking / binary replacement).
  * Startup mode changed (e.g., `Disabled` -> `Auto`): **MEDIUM**.

### 2.4 Scheduled Tasks
* **Identity Resolution:** Composite key `(task_path.lower(), task_name.lower())`.
* **Added Tasks:** New tasks flagged as **HIGH**; flagged as **CRITICAL** if action executes LOLBINs or scripts.
* **Modified Tasks:** Action modified flagged as **CRITICAL** (Execution redirection).

### 2.5 Network Connections
* **Identity Resolution:** Composite key `(proto, local_addr:local_port, remote_addr:remote_port)`.
* **Added Sockets:**
  * Remote port matches known C2/Trojan ports (`4444`, `1337`, `6667`, `31337`, etc.): **CRITICAL**.
  * Process is a command shell (`powershell.exe`, `cmd.exe`, `wscript.exe`): **HIGH**.
  * New listening socket: **LOW** / **INFO**.
  * Standard outbound HTTPS (e.g., port 443 by browser): **INFO**.

### 2.6 Volatile Security Files
* **Identity Resolution:** Case-insensitive file path (`path.lower()`).
* **Added Files:**
  * Executable disguised with double extension (`.pdf.exe`, `.docx.vbs`): **CRITICAL**.
  * Executable dropped in `Downloads` or `Temp`: **HIGH**.
  * Benign non-executable files: **INFO**.
* **Modified Files:**
  * Binary file contents changed (`sha256` or `size` mismatch): **HIGH**.

### 2.7 Browser Footprint
* New browser extension flagged as **CRITICAL** if matches suspicious extension signatures.

---

## 3. Risk Weighting & Verdict Classification

Every detected diff item receives a `risk_level` and an explainable list of `reasons`. The engine summarizes overall state into an automated triage verdict:

| Verdict | Color | Trigger Criteria |
|---|---|---|
| **`CRITICAL THREATS OBSERVED`** | `#ef4444` | $\ge 1$ changes with `risk_level == "CRITICAL"` (e.g. active C2 socket, double-extension binary, ransomware command). |
| **`SUSPICIOUS ACTIVITY DETECTED`** | `#f97316` | $\ge 1$ changes with `risk_level == "HIGH"` (e.g. new RunKey persistence, process in Temp). |
| **`HOST DRIFT / POLICY WARNING`** | `#eab308` | Only `MEDIUM` changes (e.g. service startup mode changed, suspicious process terminated). |
| **`BENIGN SYSTEM CHANGES`** | `#3b82f6` | Normal additions/removals (e.g. browser opened temporary sockets, standard software update). |
| **`NO STATE CHANGES DETECTED`** | `#22c55e` | Zero additions, removals, or modifications between snapshots. |

---

## 4. REST API Reference

### 4.1 `GET /api/agent/diff/latest`
Compares the most recent snapshot on disk against its immediate predecessor.

**Sample Response (HTTP 200):**
```json
{
  "diff_id": "diff_b88b420f",
  "base_snapshot_id": "snap_20260925_131407_dff57d",
  "target_snapshot_id": "snap_20260925_131503_ac5af2",
  "generated_at": "2026-09-25T13:21:09.123456+00:00",
  "base_timestamp": "2026-09-25T13:14:07.123456+00:00",
  "target_timestamp": "2026-09-25T13:15:03.789012+00:00",
  "time_delta_seconds": 55.62,
  "summary": {
    "total_added": 18,
    "total_removed": 10,
    "total_modified": 0,
    "total_security_relevant": 0,
    "critical_changes": 0,
    "high_risk_changes": 0,
    "medium_risk_changes": 0,
    "verdict": "BENIGN SYSTEM CHANGES",
    "verdict_color": "#3b82f6",
    "is_baseline_only": false
  },
  "categories": {
    "processes": {
      "category": "processes",
      "added_count": 2,
      "removed_count": 1,
      "modified_count": 0,
      "security_relevant_count": 0,
      "items": []
    },
    "persistence": {
      "category": "persistence",
      "added_count": 0,
      "removed_count": 0,
      "modified_count": 0,
      "security_relevant_count": 0,
      "items": []
    }
  },
  "security_relevant_changes": []
}
```

---

### 4.2 `GET /api/agent/diff?base_id={id}&target_id={id}`
Computes the security diff between two specific snapshot IDs.

* **Query Parameters:**
  * `target_id` (optional): Defaults to newest snapshot if omitted.
  * `base_id` (optional): Automatically resolves to the snapshot created immediately prior to `target_id` if omitted.

**Status Codes:**
* `200 OK`: Diff successfully computed.
* `404 Not Found`: Either `base_id` or `target_id` does not exist on disk.
