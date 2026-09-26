# Pasha 2.0 — Milestone 9: Risk vs. Confidence Metric Separation

## 1. Problem Statement & Mathematical Rationale

Traditional endpoint security platforms compress threat evaluation into a single scalar "Threat Score" (e.g. 85/100). This conflation leads to serious operational hazards:
* **The False-Positive Disaster**: A heuristic alert (e.g., an unsigned PowerShell script running in a temporary directory) is scored as "High Severity", triggering automated process kills or quarantined system files when it was merely an administrative updater.
* **The Delayed Response Dilemma**: A confirmed, weaponized malware strain is scored at "Medium Severity" because it executed fewer API calls, causing operators to postpone triage.

**Milestone 9: Risk vs. Confidence Metric Separation** mathematically decouples the analysis into two orthogonal dimensions:
1. **Risk Severity ($R \in [0, 100]$)**: *If this artifact is malicious, what is the magnitude of potential harm?* (e.g., Ransomware encryption, LSASS memory injection, credential dumping vs. harmless adware).
2. **Evidentiary Confidence ($C \in [0, 100\%]$)**: *How conclusive is our proof?* (e.g., Deterministic YARA signature matches, confirmed C2 network traffic vs. uncorroborated single-signal heuristics).

---

## 2. The Operational Decision Matrix (Action Quadrants)

Combining $(R, C)$ yields four distinct operational action classifications:

```
    Evidentiary Confidence (0% - 100%)
           ▲
           │  URGENT ANALYST REVIEW      │  AUTOMATED CONTAINMENT
           │  (High Risk, Low Confidence)│  (High Risk, High Confidence)
      100% ┼─────────────────────────────┼──────────────────────────────
           │  e.g., Unconfirmed script   │  e.g., Confirmed WannaCry
           │  with file deletion API     │  with YARA hit + C2 beacon
           │                             │
           ├─────────────────────────────┼──────────────────────────────
           │  OBSERVE & LOG              │  SCHEDULED INVESTIGATION
           │  (Low Risk, Low Confidence) │  (Moderate Risk, Moderate Conf)
           │  e.g., Routine anomaly,     │  e.g., Adware or suspicious
           │  background telemetry       │  scheduled task
        0% ┼─────────────────────────────┼──────────────────────────────►
           0%                           50%                          100%
                                Risk Severity
```

### Action Classifications:
1. **`AUTOMATED_CONTAINMENT`** ($R \ge 75 \text{ and } C \ge 75\%$):
   Conclusive proof of critical danger. The system can safely execute containment actions (kill PID, isolate file, delete RunKey) without risk of disruptive false positives.
2. **`URGENT_ANALYST_REVIEW`** ($R \ge 75 \text{ and } C < 75\%$):
   High potential danger, but proof is speculative or incomplete. Automated destruction is held; an immediate high-priority ticket is presented to the human analyst.
3. **`SCHEDULED_INVESTIGATION`** ($40 \le R < 75$):
   Moderate danger with variable certainty. Queued for standard forensic triage.
4. **`OBSERVE_AND_LOG`** ($R < 40$):
   Minor anomaly. Recorded in local telemetry without alerting the user.

---

## 3. Data Models (`backend/agent/models/metrics.py`)

### 3.1 EvidenceFactor
Represents an isolated evidentiary signal:
- `factor_name`: Description (e.g., "YARA Signature Matches", "Process Memory Injection Observed").
- `factor_type`: Category (`DETERMINISTIC_SIGNATURE`, `BEHAVIORAL_TELEMETRY`, `HEURISTIC_ANOMALY`, `HOST_CONTEXT`).
- `weight`: Mathematical multiplier (1.0 to 1.8).
- `risk_contribution`: Incremental impact score ($0\text{--}100$).
- `confidence_contribution`: Incremental certainty score ($0\text{--}100$).
- `description`: Plain-language explanation.
- `evidence_data`: Structured evidence payload (matched rule names, call arguments, remote IPs).

### 3.2 DualThreatMetrics
- `metric_id`: Unique identifier (`metric_<hex>`).
- `candidate_id`: ID of the evaluated candidate.
- `risk_score`: 0–100 integer.
- `confidence_score`: 0–100% integer.
- `risk_tier`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`.
- `confidence_tier`: `CONFIRMED`, `HIGH_CONFIDENCE`, `MODERATE`, `SPECULATIVE`.
- `action_classification`: One of the four decision quadrants.
- `factors`: List of contributing `EvidenceFactor` items.
- `rationale`: Executive synthesis explaining why the action was recommended.

---

## 4. Evaluation Engine (`backend/agent/security/metrics.py`)

The function `evaluate_dual_metrics(candidate, report=None, snapshot=None, diff=None) -> DualThreatMetrics`:
1. Evaluates heuristic and host context factors (Temp directory execution, initial detector triggers).
2. Evaluates deterministic static signatures (YARA matches, Shannon entropy thresholds).
3. Evaluates behavioral telemetry (memory injection API streams, startup RunKeys, C2 network connections).
4. Evaluates differential emergence from sequential security snapshots.
5. Normalizes scores:
   - **Confidence Guardrail**: Candidates lacking dynamic sandbox reports have confidence strictly capped at $50\%$ to guarantee that speculative alerts cannot trigger automated containment.
6. Maps into the Action Matrix and generates executive rationale.

---

## 5. REST API Endpoints (`backend/main.py`)

### 5.1 `GET /api/agent/metrics/latest`
Evaluates dual metrics for the latest investigated candidate.
- **Response**: `DualThreatMetrics` JSON schema.
- **Status Codes**:
  - `200 OK`: Metrics evaluated.
  - `404 Not Found`: No candidates found.

### 5.2 `GET /api/agent/metrics/{candidate_id}`
Evaluates dual metrics for a specific candidate.
- **Parameters**: `candidate_id` (string).
- **Response**: `DualThreatMetrics` JSON schema.
- **Status Codes**:
  - `200 OK`: Metrics evaluated.
  - `404 Not Found`: Candidate not found.

---

## 6. Verification & Testing

Milestone 9 is verified by unit tests in `backend/test_agent.py`:
- `test_dual_threat_metrics_computation`:
  - Validates Case 1 (High Risk & High Confidence) $\rightarrow$ `AUTOMATED_CONTAINMENT`.
  - Validates Case 2 (Speculative candidate with no sandbox report) $\rightarrow$ Confidence capped $\le 50\%$, yielding `URGENT_ANALYST_REVIEW`.
- `test_dual_threat_metrics_api_endpoints`: Verifies `/api/agent/metrics/latest`, `/api/agent/metrics/{candidate_id}`, and 404 handling.
- `backend/run_tests.py`: 100% pass across all 9 pipeline and agent suites.
