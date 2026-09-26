# Pasha 2.0 — Milestone 7: Security Timeline Reconstruction

## 1. Overview & Forensic Motivation

During active incident triage, security analysts and incident responders must answer a critical question:
> *"What happened, in what sequence, before and after this event was flagged?"*

Isolated alerts fail to provide temporal context. **Milestone 7: Security Timeline Reconstruction** introduces an automated event sequencing engine. It reconstructs an end-to-end, chronological forensic timeline across:
1. **Host Process Inception**: Exact execution timestamps, parent-child process chains, and command lines.
2. **Volatile Filesystem Drops**: Files created or modified in temporary or AppData storage.
3. **Persistence Configuration**: Startup registry Run keys and scheduled task hooks.
4. **Differential State Shifts**: Dynamic changes detected between host security snapshots.
5. **Behavioral Sandbox Stream**: Sub-second API call tracing, memory injections, payload drops, and network beacons.
6. **Adversary ATT&CK Mapping**: Chronologically anchored MITRE technique attributions.

---

## 2. Data Models (`backend/agent/models/timeline.py`)

### 2.1 TimelineEvent
Represents a discrete security event anchored in time:
- `event_id`: Unique identifier (e.g. `evt_cand_...`, `evt_proc_...`, `evt_api_...`).
- `timestamp`: ISO-8601 formatted timestamp string.
- `relative_time_seconds`: Float delta relative to the timeline anchor ($T_0 = 0.0$ s).
- `category`: Domain category (`process`, `filesystem`, `persistence`, `network`, `api_call`, `detection`, `mitre`).
- `severity`: Standard severity level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- `source`: Telemetry generator (`host_snapshot`, `security_diff`, `behavioral_sandbox`, `candidate_detector`, `mitre_mapper`).
- `title`: Short human-readable title (e.g., `Process Spawned: powershell.exe (PID: 4120)`).
- `description`: Plain-language explanation with command line, arguments, or file paths.
- `details`: Structured attributes (PID, PPID, executable path, remote IP/port, API arguments).
- `related_indicators`: Correlated observables (IPs, hashes, paths).

### 2.2 SecurityTimeline
Forensic timeline container:
- `timeline_id`: Unique timeline identifier (`timeline_<hex>`).
- `target_id`: Identifier of the candidate, snapshot, or host.
- `target_type`: Scope (`candidate`, `snapshot`, `global`).
- `generated_at`: ISO timestamp of generation.
- `start_time`: Timestamp of earliest event ($T_0$).
- `end_time`: Timestamp of latest event ($T_{final}$).
- `total_events`: Count of chronological events.
- `event_counts_by_category`: Summary breakdown (e.g. `{"process": 2, "api_call": 10, "network": 1}`).
- `event_counts_by_severity`: Summary breakdown (e.g. `{"HIGH": 5, "CRITICAL": 1}`).
- `events`: Chronologically sorted list of `TimelineEvent` records.

---

## 3. Timeline Engine (`backend/agent/security/timeline.py`)

The reconstruction function `reconstruct_security_timeline(candidate=None, report=None, snapshot=None, diff=None) -> SecurityTimeline`:
1. Establishes the baseline anchor epoch ($T_0$) from the candidate's discovery or snapshot timestamp.
2. Extracts candidate detection metadata.
3. Harvests host process creation times, volatile file timestamps, and registry startup configurations.
4. Integrates security diff state changes.
5. Ingests behavioral sandbox execution streams, anchoring emulated sub-second API logs ($T_0 + \Delta t$).
6. Normalizes all timestamps into unified epoch floats and performs strict chronological sorting.
7. Calculates `relative_time_seconds` for each event from $T_0$.
8. Synthesizes category and severity aggregation metrics.

---

## 4. REST API Endpoints (`backend/main.py`)

### 4.1 `GET /api/agent/timeline/latest`
Reconstructs the forensic timeline for the latest analyzed suspicious candidate or most recent host snapshot.
- **Response**: `SecurityTimeline` JSON schema.
- **Status Codes**:
  - `200 OK`: Timeline successfully reconstructed.
  - `404 Not Found`: No candidates or snapshots found.

### 4.2 `GET /api/agent/timeline/snapshot/{snapshot_id}`
Reconstructs the forensic timeline across all events within a specific host snapshot.
- **Parameters**: `snapshot_id` (string).
- **Response**: `SecurityTimeline` JSON schema.
- **Status Codes**:
  - `200 OK`: Snapshot timeline reconstructed.
  - `404 Not Found`: Specified snapshot not found.

### 4.3 `GET /api/agent/timeline/{candidate_id}`
Reconstructs the chronological forensic timeline for a specific suspicious candidate.
- **Parameters**: `candidate_id` (string).
- **Response**: `SecurityTimeline` JSON schema.
- **Status Codes**:
  - `200 OK`: Candidate timeline reconstructed.
  - `404 Not Found`: Candidate not found.

---

## 5. Verification & Testing

Milestone 7 is covered by automated unit tests in `backend/test_agent.py`:
- `test_security_timeline_reconstruction`: Validates multi-source event extraction, category classification, and strict chronological ordering ($\Delta t_i \le \Delta t_{i+1}$).
- `test_security_timeline_api_endpoints`: Tests REST endpoints `/api/agent/timeline/latest`, `/api/agent/timeline/{candidate_id}`, `/api/agent/timeline/snapshot/{snapshot_id}`, and verifies error handling (404).
- `backend/run_tests.py`: Confirms 100% pass across all 9 pipeline and agent suites.
