# Pasha 2.0 — Milestone 6: Evidence Correlation & Attack Story

## 1. Overview & Objective

In **Pasha 2.0**, automated investigation produces a rich set of isolated findings: static binary metrics, YARA rule hits, emulated API logs, filesystem drops, registry alterations, network beacons, extracted IOCs, and MITRE ATT&CK techniques.

However, a raw dump of disconnected JSON fields overwhelms security analysts and incident responders. 

**Milestone 6: Evidence Correlation & Attack Story** bridges the gap between raw detection and actionable intelligence. It implements a deterministic graph correlation engine that transforms disparate security telemetry into:
1. An interconnected, directed **Evidence Graph** ($G = (V, E)$).
2. A chronological, multi-phase **Attack Story** narrative explaining how the threat initiated, persisted, communicated, and aligned with MITRE adversary tactics.

---

## 2. Data Models (`backend/agent/models/correlation.py`)

### 2.1 EvidenceNode
Represents an individual entity or observation in the security domain.
- `id`: Unique node identifier (e.g. `node_root_cand_...`, `node_file_a3f1...`, `node_net_185_190_...`, `node_mitre_T1547`).
- `type`: Category (`candidate`, `file`, `yara`, `persistence`, `network`, `ioc`, `mitre`).
- `label`: Concise human-readable title.
- `severity`: Standard severity level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- `details`: Rich metadata dictionary (hashes, paths, IPs, ports, descriptions).

### 2.2 EvidenceEdge
Represents a causal, temporal, or attribution relationship between two nodes.
- `source`: Source node ID.
- `target`: Target node ID.
- `relation`: Relationship type (`IDENTIFIED_AS`, `ASSOCIATED_BINARY`, `MATCHED_SIGNATURE`, `REGISTERED_PERSISTENCE`, `DROPPED`, `COMMUNICATED_WITH`, `EXPOSED_INDICATOR`, `EXEMPLIFIES_TECHNIQUE`).
- `label`: Short human-readable edge annotation.
- `confidence`: Confidence rating ($0.0$ to $1.0$).

### 2.3 AttackStoryPhase
A structured chapter in the attack narrative.
- `phase_name`: e.g. "Initial Discovery & Host Context", "Signature Evaluation & Static Characteristics", "Host Modifications & Persistence", "Command & Control and Indicator Extraction", "MITRE ATT&CK Correlation".
- `tactic`: Primary MITRE ATT&CK tactic category.
- `narrative`: Plain-language explanation synthesized from findings.
- `node_ids`: List of node IDs relevant to this phase.

### 2.4 AttackStory & AttackStoryGraph
- `story_id`: Unique identifier (`story_<hex>`).
- `candidate_id`: ID of the investigated candidate.
- `report_id`: ID of the linked malware analysis report.
- `snapshot_id`: ID of the host snapshot.
- `title`: e.g. "Confirmed Host Threat Sequence: suspicious_updater.exe".
- `verdict`: Final synthesized verdict (`CRITICAL`, `MALICIOUS`, `SUSPICIOUS`, `LOW RISK`).
- `threat_score`: 0–100 threat score.
- `confidence_score`: 0–100% evidentiary confidence rating.
- `summary_narrative`: High-level executive summary.
- `phases`: List of `AttackStoryPhase` chapters.
- `graph`: The complete `AttackStoryGraph` (nodes and edges).
- `root_cause_node_id`: Node ID of the primary trigger.

---

## 3. Correlation Engine Architecture (`backend/agent/security/correlation.py`)

The function `correlate_evidence(candidate, report=None, snapshot=None) -> AttackStory` executes a 5-phase correlation pipeline:

```
[Candidate Trigger]
       │
       ├─► (Phase 1) Initial Host Discovery (Process / File / RunKey)
       │
       ├─► (Phase 2) Binary Hashes + YARA Signatures + Entropy
       │
       ├─► (Phase 3) Host Modifications: Persistence RunKeys + Dropped Payloads
       │
       ├─► (Phase 4) Command & Control Beacons + Extracted IOC IPs
       │
       └─► (Phase 5) MITRE ATT&CK Matrix Mapping (T1547, T1059, etc.)
```

### Phase Breakdown
1. **Initial Discovery**:
   - Creates the Root Cause Node (`type="candidate"`).
   - Extracts contextual host metadata (PID, CommandLine, Path, RunKey location).
   - Generates the initial discovery narrative.

2. **Static Characteristics & Signatures**:
   - If an executable hash is available, creates a Binary File Node (`type="file"`) linked via `ASSOCIATED_BINARY`.
   - Evaluates YARA signature rule matches, creates `yara` nodes, and links them via `MATCHED_SIGNATURE`.

3. **Host Modifications & Persistence**:
   - Parses behavioral telemetry (supporting both dictionary and list formats).
   - Creates `persistence` nodes for startup RunKeys linked via `REGISTERED_PERSISTENCE`.
   - Creates `file` nodes for dropped payloads linked via `DROPPED`.

4. **Command & Control and Indicators**:
   - Correlates outbound network activity and C2 beacons (`COMMUNICATED_WITH`).
   - Correlates extracted IPv4 indicators (`EXPOSED_INDICATOR`).

5. **MITRE ATT&CK Attribution**:
   - Links identified MITRE techniques (e.g., Persistence, Execution, Defense Evasion) via `EXEMPLIFIES_TECHNIQUE`.

---

## 4. REST API Endpoints (`backend/main.py`)

### 4.1 `GET /api/agent/attack-story/latest`
Generates or retrieves the Attack Story for the most recently investigated candidate.
- **Response**: Full `AttackStory` JSON schema.
- **Status Codes**:
  - `200 OK`: Story successfully correlated.
  - `404 Not Found`: No investigated candidates exist in the queue yet.

### 4.2 `GET /api/agent/attack-story/{candidate_id}`
Generates or retrieves the Attack Story for a specific candidate ID.
- **Parameters**: `candidate_id` (string).
- **Response**: Full `AttackStory` JSON schema.
- **Status Codes**:
  - `200 OK`: Story successfully correlated.
  - `404 Not Found`: Specified candidate not found.

---

## 5. Verification & Testing

Milestone 6 is verified by automated test suites:
- `backend/test_agent.py`:
  - `test_evidence_correlation_and_attack_story`: Verifies complete 5-phase graph generation, node labels, edge relationships, confidence calculation, and narrative synthesis.
  - `test_attack_story_api_endpoints`: Verifies FastAPI routes `/api/agent/attack-story/latest` and `/api/agent/attack-story/{candidate_id}`.
- `backend/run_tests.py`:
  - Full regression test across all 9 analysis and agent pipeline suites.
