# PASHA 2.0 — SUSPICIOUS CANDIDATE DETECTION & INVESTIGATION QUEUE

**Document Version:** 2.0.0  
**Status:** Implemented & Verified (Milestone 4 Completed)  
**Target Platform:** Windows 10/11 (Local-First Architecture)  

---

## 1. Overview & Objective

In Pasha 1.x, analysis was strictly manual: an analyst uploaded a suspect file or clicked a preset malware sample.

In **Pasha 2.0**, candidate detection is **autonomous**:
1. The **Local Agent** captures Windows telemetry and creates **Security Snapshots** (Milestone 1 & 2).
2. The **Security Diff Engine** isolates newly added or modified state changes (Milestone 3).
3. The **Candidate Detector** inspects both snapshots and diffs to extract high-risk targets.
4. The **Candidate Queue** prioritizes, scores, and manages candidate lifecycles, ready for automated deep analysis (Milestones 5–10).

```
┌────────────────────────────────┐     ┌────────────────────────────────┐
│      SECURITY SNAPSHOT         │     │         SECURITY DIFF          │
│ (Pre-screened Anomalies)       │     │ (New / Modified State Changes) │
└───────────────┬────────────────┘     └───────────────┬────────────────┘
                │                                      │
                └──────────────────┬───────────────────┘
                                   │
                                   ▼
                ┌──────────────────────────────────────┐
                │          CANDIDATE DETECTOR          │
                │  • Explainable Priority Scoring (0-100)
                │  • Local File / Hash Resolution      │
                │  • Source Attribution (`snapshot`/`diff`)
                └──────────────────┬───────────────────┘
                                   │
                                   ▼
                ┌──────────────────────────────────────┐
                │          CANDIDATE QUEUE             │
                │  • Deduplication Engine              │
                │  • Priority Sorted (Highest First)   │
                │  • Lifecycle: DISCOVERED -> QUEUED   │
                │    -> ANALYZING -> ANALYZED          │
                └──────────────────┬───────────────────┘
                                   │
                                   ▼ (Milestone 5)
                ┌──────────────────────────────────────┐
                │     PASHA MALWARE ANALYSIS ENGINES   │
                │  Static, YARA, Behavioral Sandbox,   │
                │  IOC Extractor, MITRE ATT&CK Mapper  │
                └──────────────────────────────────────┘
```

---

## 2. Candidate Lifecycle States

Every candidate progresses through defined lifecycle states:

```
 [ DISCOVERED ] ──(Auto/Manual Queue)──► [ QUEUED ]
        │                                    │
        │                                    ▼ (Worker Picks Up)
 (Ignore / Whitelist)                  [ ANALYZING ]
        │                                    │
        ▼                                    ▼ (Analysis Completed)
   [ IGNORED ]                          [ ANALYZED ] ──► (Linked to Report ID)
```

| Status | Description |
|---|---|
| **`DISCOVERED`** | Flagged as an anomaly by collector heuristics or security diff; pending triage. |
| **`QUEUED`** | Prioritized in queue, waiting for investigation by analysis engines. |
| **`ANALYZING`** | Currently undergoing Static inspection, YARA signature evaluation, or Behavioral emulation. |
| **`ANALYZED`** | Deep analysis completed; linked to a `FullAnalysisReport` via `analysis_report_id`. |
| **`IGNORED`** | Marked as false-positive or suppressed by analyst. |

---

## 3. Explainable Priority Scoring Algorithm

Candidates receive an explainable numerical priority score between **0 and 100** to guarantee that the most critical threats are investigated first:

| Threat Signal | Score Weight | Rationale |
|---|---|---|
| **Ransomware / Shadow Deletion Indicators** | `+45` | Keywords: `vssadmin delete shadows`, `bcdedit recoveryenabled no`. |
| **Credential Dumping Indicators** | `+40` | Keywords: `mimikatz`, `lazagne`, `lsass` targeting. |
| **Encoded / Obfuscated Commands** | `+35` | Flags: `-enc`, `-encodedcommand`, hidden window styles. |
| **Double Extension Disguise** | `+35` | Patterns: `.pdf.exe`, `.docx.vbs`, `.txt.scr`. |
| **C2 / Trojan Port Network Sockets** | `+30` | Ports: `4444`, `1337`, `6667`, `31337`, `8888`, etc. |
| **User-Writable Path Execution (Temp/AppData)** | `+25` | Binary located in `AppData\Local\Temp` or non-standard profiles. |
| **Script Persistence Mechanism** | `+25` | Registry RunKey or Startup item invoking `.vbs`, `.ps1`, `.bat`, `.hta`. |
| **Service Binary Hijacking / User Path** | `+30` | Service binary modified or pointing to user profile path. |
| **Command Shell Network Socket** | `+25` | Network connection opened by `powershell.exe`, `cmd.exe`, or `wscript.exe`. |
| **Delta Modifier (New State Change in Diff)** | `+10` | Fresh state changes detected between snapshots receive higher urgency. |

*Base score:* `25`. Resulting score is clamped between `15` and `100`.

---

## 4. Candidate Data Model

### `SuspiciousCandidate`
```json
{
  "candidate_id": "cand_proc_4444_e3b0c4",
  "snapshot_id": "snap_20260925_131407_dff57d",
  "category": "process",
  "name": "powershell.exe",
  "target_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "cmdline": "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA...",
  "sha256": "8a3e7b1c...",
  "size_bytes": 450560,
  "discovery_source": "snapshot_collector",
  "heuristics_matched": [
    "Encoded PowerShell Command Execution",
    "Hidden Window Process Spawning"
  ],
  "priority_score": 85,
  "status": "QUEUED",
  "discovered_at": "2026-09-25T13:14:07.123456+00:00",
  "analysis_report_id": null,
  "metadata": {
    "pid": 4444,
    "user": "DOMAIN\\analyst",
    "integrity_level": "High"
  }
}
```

---

## 5. Queue Storage & Deduplication Engine

* **Persistent Storage File:** `backend/agent/data/candidate_queue.json`
* **Intelligent Deduplication:**
  * Candidates are fingerprinted by cryptographic hash (`sha256`), canonical target path (`category:path`), or unique command line.
  * If the same binary or command line is re-discovered across multiple snapshots, the queue **does not duplicate entries**. Instead, it merges newly discovered heuristic reasons, updates the priority score to the highest observed value, and preserves existing analysis progress (`ANALYZED` / `report_id`).

---

## 6. REST API Reference

### 6.1 `GET /api/agent/candidates`
Lists candidates sorted descending by priority score. Supports filtering by `status` and `category`.

**Query Parameters:**
* `status` (optional): `DISCOVERED`, `QUEUED`, `ANALYZING`, `ANALYZED`, `IGNORED`.
* `category` (optional): `process`, `file`, `persistence`, `service`, `scheduled_task`, `network`.
* `limit` (default `50`), `offset` (default `0`).

---

### 6.2 `GET /api/agent/candidates/summary`
Returns aggregate queue statistics for dashboard visualization.

**Sample Response:**
```json
{
  "total_candidates": 4,
  "by_status": {
    "QUEUED": 3,
    "ANALYZED": 1
  },
  "by_category": {
    "process": 1,
    "file": 1,
    "service": 1,
    "scheduled_task": 1
  },
  "highest_priority_score": 85,
  "top_candidates": [ ... ]
}
```

---

### 6.3 `GET /api/agent/candidates/next`
Retrieves the highest-priority candidate ready for investigation (`status == "QUEUED"` or `"DISCOVERED"`). Returns `HTTP 404` if queue is empty.

---

### 6.4 `POST /api/agent/candidates/detect`
Triggers candidate detection on-demand.

**Request Body (optional):**
```json
{
  "snapshot_id": "snap_20260925_131407_dff57d",
  "auto_queue": true
}
```
*If no `snapshot_id` is supplied, automatically evaluates the latest snapshot and latest security diff.*

---

### 6.5 `PATCH /api/agent/candidates/{candidate_id}/status`
Updates candidate lifecycle state.

**Request Body:**
```json
{
  "status": "ANALYZED",
  "analysis_report_id": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

---

### 6.6 `DELETE /api/agent/candidates/{candidate_id}`
Removes a candidate from the queue.
