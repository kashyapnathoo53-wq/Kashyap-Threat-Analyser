# Pasha 2.0 — Milestone 8: Impact & Blast Radius Analysis

## 1. Overview & Operational Goal

Once an alert or candidate is investigated, security operators and incident response leads need to immediately answer:
> *"What is the full blast radius? How far did this compromise reach, and what exact steps are required to contain it?"*

**Milestone 8: Impact & Blast Radius Analysis** computes the complete system footprint of an identified threat. It identifies all affected host processes, volatile filesystem drops, registry persistence hooks, and network connections, calculates an overall Impact Index ($0\text{--}100$), classifies the scope level, and produces actionable, prioritized containment actions.

---

## 2. Data Models (`backend/agent/models/blast_radius.py`)

### 2.1 AffectedEntity
Represents a specific component of the operating system impacted by the threat:
- `entity_type`: Category (`process`, `file`, `registry`, `network`, `account`).
- `identifier`: Primary target identifier (e.g. PID, absolute path, registry key, IP:Port).
- `name`: Human-readable label.
- `impact_type`: Nature of the impact (`SPAWNED`, `INJECTED`, `DROPPED`, `MODIFIED`, `PERSISTED`, `BEACONED`).
- `severity`: Severity level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- `details`: Rich diagnostic metadata dictionary.

### 2.2 ContainmentAction
Actionable remediation step recommended to isolate or eliminate the threat:
- `action_id`: Unique identifier (`act_<hex>`).
- `target_type`: Scope (`process`, `file`, `registry`, `network`).
- `target`: Action target (PID, file path, registry key, IP address).
- `action`: Specific operation (`TERMINATE`, `QUARANTINE`, `DELETE_KEY`, `BLOCK_FIREWALL`).
- `description`: Plain-language explanation of the remediation.
- `urgency`: Priority (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).

### 2.3 BlastRadiusReport
Top-level impact evaluation report:
- `report_id`: Unique report ID (`blast_<hex>`).
- `candidate_id`: ID of the investigated candidate.
- `candidate_name`: Display name.
- `scope_level`: Qualitative classification:
  - `CONTAINED`: Isolated to candidate artifact with zero lateral or persistent host footprint.
  - `LOCAL_SURFACE`: Minor temporary drops or single child process.
  - `PERSISTED`: Configured startup mechanisms or survival hooks.
  - `HOST_WIDE_COMPROMISE`: Injected into system processes, persistence established, and active C2 beaconing.
- `blast_score`: Numerical index ($0\text{--}100$).
- `total_affected_entities`: Total count of impacted system items.
- `affected_processes`: List of spawned, injected, or altered processes.
- `affected_files`: List of dropped or modified filesystem artifacts.
- `affected_registry`: List of altered or created registry keys.
- `affected_network`: List of active sockets and contacted C2 endpoints.
- `summary_narrative`: Executive summary.
- `containment_actions`: Prioritized list of containment steps.

---

## 3. Analysis Engine (`backend/agent/security/blast_radius.py`)

The function `compute_blast_radius(candidate, report=None, snapshot=None, diff=None) -> BlastRadiusReport`:
1. **Candidate Root Assessment**: Evaluates primary candidate process PID, file image, and execution context.
2. **Emulated Execution Tracing**:
   - Traverses process trees to discover spawned child processes.
   - Analyzes API call streams to identify memory injection targets (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`).
   - Extracts all volatile payload drops and modified paths.
   - Extracts all persistence Run keys and startup values.
   - Extracts outbound HTTP/TCP sockets and beacon destinations.
3. **Live Snapshot Correlation**: Links candidate PID to live operating system socket bindings.
4. **Deterministic Containment Generation**: Produces targeted commands (`TERMINATE`, `QUARANTINE`, `DELETE_KEY`, `BLOCK_FIREWALL`) for every affected entity.
5. **Scoring & Scope Classification**: Synthesizes a weighted blast index and assigns the final scope level.

---

## 4. REST API Endpoints (`backend/main.py`)

### 4.1 `GET /api/agent/blast-radius/latest`
Computes the Impact & Blast Radius for the latest investigated candidate.
- **Response**: `BlastRadiusReport` JSON schema.
- **Status Codes**:
  - `200 OK`: Blast radius successfully computed.
  - `404 Not Found`: No candidates available to evaluate.

### 4.2 `GET /api/agent/blast-radius/{candidate_id}`
Computes the Impact & Blast Radius for a specific suspicious candidate.
- **Parameters**: `candidate_id` (string).
- **Response**: `BlastRadiusReport` JSON schema.
- **Status Codes**:
  - `200 OK`: Blast radius computed for candidate.
  - `404 Not Found`: Specified candidate not found.

---

## 5. Verification & Testing

Milestone 8 is validated by automated tests:
- `backend/test_agent.py`:
  - `test_blast_radius_computation`: Validates entity extraction across processes, files, registry keys, and network beacons, score thresholds, scope levels, and containment action generation.
  - `test_blast_radius_api_endpoints`: Tests `/api/agent/blast-radius/latest`, `/api/agent/blast-radius/{candidate_id}`, and 404 behavior.
- `backend/run_tests.py`: Confirms 100% clean execution across all 9 pipeline and agent suites.
