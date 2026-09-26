# Pasha 2.0 — Milestone 10: User-Confirmed Response & Remediation Engine

## 1. Overview & Core Philosophy

In traditional EDR platforms, automated or unchecked endpoint responses frequently cause catastrophic system outages—such as terminating legitimate user processes or deleting critical operating system binaries due to false positives.

**Milestone 10: User-Confirmed Response & Remediation** implements a safe, deterministic, and guarded response framework founded on three principles:
1. **Explicit Confirmation**: Every destructive or state-altering remediation action requires an unguessable, cryptographically generated confirmation token (`confirmation_token`).
2. **Hardcoded System Whitelists & Guardrails**: System-critical processes (`explorer.exe`, `csrss.exe`, `lsass.exe`, `services.exe`, `smss.exe`, `svchost.exe`, `wininit.exe`, `winlogon.exe`) and core Windows directories (`C:\Windows`, `C:\Windows\System32`) can **never** be terminated or quarantined under any circumstances.
3. **Reversible Quarantine Vault**: Instead of permanent deletion (which destroys forensic evidence and risks irrecoverable data loss), files are encrypted/isolated into the local Pasha Quarantine Vault (`backend/agent/data/quarantine/`), with one-click restoration support.

---

## 2. Data Models (`backend/agent/models/remediation.py`)

### 2.1 RemediationActionType
- `TERMINATE_PROCESS`: Terminates an active process by PID or image name.
- `QUARANTINE_FILE`: Moves an artifact to the secure quarantine vault.
- `REMOVE_REGISTRY_RUNKEY`: Disables or deletes an autorun startup hook.
- `BLOCK_FIREWALL_IP`: Blocks outbound egress communication to a C2 IP.

### 2.2 RemediationPlanItem
- `item_id`: Unique identifier (`item_<hex>`).
- `action_type`: One of the four remediation action types.
- `target`: Action target (PID, file path, registry key, IP address).
- `target_name`: Human-readable title.
- `description`: Plain-language remediation explanation.
- `safety_check`: Guardrail check result (`SAFE`, `PROTECTED_SYSTEM_ENTITY`, `INVALID_TARGET`).
- `is_safe`: Boolean guardrail flag.
- `status`: Lifecycle state (`PENDING_CONFIRMATION`, `EXECUTED`, `FAILED`, `BLOCKED_BY_GUARDRAIL`, `ROLLED_BACK`).
- `requires_confirmation`: Explicit confirmation requirement (default `True`).
- `confirmation_token`: Random unguessable token (`pasha_conf_<hex>`).

### 2.3 RemediationPlan
- `plan_id`: Unique plan ID (`plan_<hex>`).
- `candidate_id`: ID of the investigated threat.
- `candidate_name`: Display title.
- `created_at`: Generation timestamp.
- `items`: Ordered list of `RemediationPlanItem` proposed steps.
- `is_fully_executed`: Flag tracking complete execution.

### 2.4 QuarantinedFileRecord
- `quarantine_id`: Unique vault record ID (`quar_<hex>`).
- `original_path`: Absolute path on the host prior to quarantine.
- `quarantine_vault_path`: Encapsulated storage path (`.pasha_quarantine`).
- `filename`: Original filename.
- `sha256`: Cryptographic hash before isolation.
- `quarantined_at`: Timestamp of quarantine.
- `file_size_bytes`: Byte size.
- `can_restore`: Boolean tracking restoration viability.

---

## 3. Remediation Engine Architecture (`backend/agent/security/remediation.py`)

### 3.1 Plan Creation (`create_plan`)
Extracts recommended actions from the candidate's blast radius containment report, runs safety checks against protected entities, and generates secure confirmation tokens.

### 3.2 Guarded Action Execution (`execute_action`)
1. Validates that the provided `confirmation_token` matches the plan item.
2. Re-verifies that the target does not violate system protection guardrails.
3. Executes the platform operation:
   - **Process Termination**: Calls `psutil.Process(pid).terminate()`, escalating to `.kill()` only if unresponsive.
   - **File Quarantine**: Computes pre-quarantine SHA256, moves the file into `backend/agent/data/quarantine/`, records metadata in `quarantine_index.json`.
   - **Registry Removal**: Backs up previous state and deletes the startup key.
   - **Firewall Containment**: Blocks outbound egress traffic.
4. Records an immutable audit log entry in `backend/agent/data/remediation_audit.json`.

### 3.3 Quarantine Vault & Rollback (`restore_quarantined_file`)
If an analyst determines that a quarantined file was a false positive:
1. Validates that the destination directory exists and has no name collision.
2. Moves the file from the vault back to its original location.
3. Updates the quarantine index.

---

## 4. REST API Endpoints (`backend/main.py`)

### 4.1 `POST /api/agent/remediation/plan/{candidate_id}`
Generates a user-confirmed remediation plan for a candidate.
- **Response**: `RemediationPlan` JSON schema.
- **Status Codes**:
  - `200 OK`: Plan created.
  - `404 Not Found`: Candidate not found.

### 4.2 `GET /api/agent/remediation/plan/{plan_id}`
Retrieves a specific remediation plan.
- **Response**: `RemediationPlan` JSON schema.
- **Status Codes**:
  - `200 OK`: Plan returned.
  - `404 Not Found`: Plan not found.

### 4.3 `POST /api/agent/remediation/execute`
Executes an individual action in a remediation plan with its confirmation token.
- **Request Body**:
  ```json
  {
    "plan_id": "plan_abc12345",
    "item_id": "item_def678",
    "confirmation_token": "pasha_conf_1a2b3c4d5e6f7a8b"
  }
  ```
- **Response**: `RemediationExecutionResult` JSON schema.
- **Status Codes**:
  - `200 OK`: Remediation successfully executed.
  - `400 Bad Request`: Invalid token, target error, or blocked by system guardrail.

### 4.4 `GET /api/agent/remediation/quarantine`
Lists all files currently secured in the quarantine vault.
- **Response**: List of `QuarantinedFileRecord` JSON objects.

### 4.5 `POST /api/agent/remediation/quarantine/restore/{quarantine_id}`
Restores a quarantined file back to its original location.
- **Response**: `{"success": true, "message": "...", "quarantine_id": "..."}`.
- **Status Codes**:
  - `200 OK`: Restored successfully.
  - `400 Bad Request`: Vault missing or destination collision.

---

## 5. Verification & Testing

Milestone 10 is tested in `backend/test_agent.py`:
- `test_remediation_plan_generation_and_safety_guardrails`:
  - Validates plan generation.
  - Verifies that attempts to terminate `explorer.exe` or quarantine `C:\Windows\System32` are flagged `PROTECTED_SYSTEM_ENTITY` and blocked.
  - Verifies token validation.
- `test_quarantine_and_restore_cycle`:
  - Tests moving a dummy payload to the quarantine vault and restoring it cleanly.
- `test_remediation_api_endpoints`:
  - Validates API endpoints `/api/agent/remediation/quarantine`, `/plan/{candidate_id}`, `/plan/{plan_id}`, `/execute`.
- `backend/run_tests.py`: 100% pass across all 9 pipeline and agent suites.
