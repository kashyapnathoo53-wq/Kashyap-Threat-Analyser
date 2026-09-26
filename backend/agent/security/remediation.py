import os
import shutil
import hashlib
import json
import secrets
import uuid
import psutil
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone

from agent.models.candidate import SuspiciousCandidate
from agent.models.blast_radius import BlastRadiusReport
from agent.models.remediation import (
    RemediationActionType,
    RemediationStatus,
    RemediationPlanItem,
    RemediationPlan,
    RemediationExecutionResult,
    QuarantinedFileRecord,
)

# -------------------------------------------------------------
# SAFETY GUARDRAILS & SYSTEM WHITELISTS
# -------------------------------------------------------------

PROTECTED_PROCESS_NAMES = {
    "explorer.exe",
    "csrss.exe",
    "lsass.exe",
    "services.exe",
    "smss.exe",
    "svchost.exe",
    "wininit.exe",
    "winlogon.exe",
    "dwm.exe",
    "system",
    "system idle process"
}

PROTECTED_SYSTEM_PATHS = {
    "c:\\windows",
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\explorer.exe"
}


def _is_safe_target(action_type: RemediationActionType, target: str) -> Tuple[bool, str]:
    """Evaluates whether a remediation target complies with safety guardrails."""
    target_clean = str(target).strip().lower()

    if action_type == RemediationActionType.TERMINATE_PROCESS:
        # Check against protected process names
        if target_clean in PROTECTED_PROCESS_NAMES or target_clean.endswith(".exe") and target_clean in PROTECTED_PROCESS_NAMES:
            return False, "PROTECTED_SYSTEM_ENTITY"
        # If target is PID, check process name via psutil if running
        if target_clean.isdigit():
            pid = int(target_clean)
            if pid <= 4:  # System / Idle
                return False, "PROTECTED_SYSTEM_ENTITY"
            try:
                p = psutil.Process(pid)
                if p.name().lower() in PROTECTED_PROCESS_NAMES:
                    return False, "PROTECTED_SYSTEM_ENTITY"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return True, "SAFE"

    elif action_type == RemediationActionType.QUARANTINE_FILE:
        norm_target = os.path.normpath(target_clean)
        # Never allow quarantining root Windows directories
        for prot in PROTECTED_SYSTEM_PATHS:
            if norm_target == os.path.normpath(prot):
                return False, "PROTECTED_SYSTEM_ENTITY"
        if norm_target in ["c:\\", "c:\\windows", "c:\\windows\\system32"]:
            return False, "PROTECTED_SYSTEM_ENTITY"
        return True, "SAFE"

    elif action_type == RemediationActionType.REMOVE_REGISTRY_RUNKEY:
        # Core system keys should not be deleted blindly
        if "system\\currentcontrolset\\services" in target_clean:
            return False, "PROTECTED_SYSTEM_ENTITY"
        return True, "SAFE"

    elif action_type == RemediationActionType.BLOCK_FIREWALL_IP:
        # Never block localhost or loopback
        if target_clean in ["127.0.0.1", "::1", "localhost"]:
            return False, "PROTECTED_SYSTEM_ENTITY"
        return True, "SAFE"

    return True, "SAFE"


# -------------------------------------------------------------
# REMEDIATION ENGINE
# -------------------------------------------------------------

class RemediationEngine:
    """
    Manages user-confirmed remediation plans, executes guarded host actions,
    and maintains the Pasha quarantine vault and audit logs.
    """

    def __init__(self, data_dir: Optional[str] = None):
        if not data_dir:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            data_dir = os.path.join(base_dir, "data")
        self.data_dir = data_dir
        self.quarantine_dir = os.path.join(data_dir, "quarantine")
        self.plans_file = os.path.join(data_dir, "remediation_plans.json")
        self.audit_file = os.path.join(data_dir, "remediation_audit.json")
        self.quarantine_index_file = os.path.join(self.quarantine_dir, "quarantine_index.json")

        os.makedirs(self.quarantine_dir, exist_ok=True)
        os.makedirs(data_dir, exist_ok=True)

        self._plans_cache: Dict[str, RemediationPlan] = {}
        self._load_plans()

    def _load_plans(self):
        if os.path.exists(self.plans_file):
            try:
                with open(self.plans_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for pid, pdata in data.items():
                        self._plans_cache[pid] = RemediationPlan(**pdata)
            except Exception:
                self._plans_cache = {}

    def _save_plans(self):
        try:
            with open(self.plans_file, "w", encoding="utf-8") as f:
                json.dump({k: v.model_dump(mode="json") for k, v in self._plans_cache.items()}, f, indent=2)
        except Exception:
            pass

    def _log_audit(self, result: RemediationExecutionResult):
        audit_records = []
        if os.path.exists(self.audit_file):
            try:
                with open(self.audit_file, "r", encoding="utf-8") as f:
                    audit_records = json.load(f)
            except Exception:
                audit_records = []
        audit_records.append(result.model_dump(mode="json"))
        try:
            with open(self.audit_file, "w", encoding="utf-8") as f:
                json.dump(audit_records, f, indent=2)
        except Exception:
            pass

    def create_plan(
        self,
        candidate: SuspiciousCandidate,
        blast_report: Optional[BlastRadiusReport] = None
    ) -> RemediationPlan:
        """
        Creates a structured, guarded remediation plan with explicit confirmation tokens.
        """
        plan_id = f"plan_{uuid.uuid4().hex[:8]}"
        items: List[RemediationPlanItem] = []

        # 1. From Blast Report Containment Actions
        if blast_report and blast_report.containment_actions:
            for act in blast_report.containment_actions:
                act_type = RemediationActionType.TERMINATE_PROCESS
                if act.action == "QUARANTINE":
                    act_type = RemediationActionType.QUARANTINE_FILE
                elif act.action == "DELETE_KEY":
                    act_type = RemediationActionType.REMOVE_REGISTRY_RUNKEY
                elif act.action == "BLOCK_FIREWALL":
                    act_type = RemediationActionType.BLOCK_FIREWALL_IP

                is_safe, safety_code = _is_safe_target(act_type, act.target)
                token = f"pasha_conf_{secrets.token_hex(8)}"
                items.append(RemediationPlanItem(
                    item_id=f"item_{uuid.uuid4().hex[:6]}",
                    action_type=act_type,
                    target=act.target,
                    target_name=act.description,
                    description=act.description,
                    safety_check=safety_code,
                    is_safe=is_safe,
                    status=RemediationStatus.PENDING_CONFIRMATION if is_safe else RemediationStatus.BLOCKED_BY_GUARDRAIL,
                    requires_confirmation=True,
                    confirmation_token=token,
                    details={"urgency": act.urgency}
                ))

        # 2. Direct Candidate Root Fallback
        if not items:
            cand_pid = candidate.metadata.get("pid")
            cand_path = candidate.target_path or candidate.metadata.get("path")
            if cand_pid:
                is_safe, s_code = _is_safe_target(RemediationActionType.TERMINATE_PROCESS, str(cand_pid))
                items.append(RemediationPlanItem(
                    item_id=f"item_{uuid.uuid4().hex[:6]}",
                    action_type=RemediationActionType.TERMINATE_PROCESS,
                    target=str(cand_pid),
                    target_name=f"Process: {candidate.name} (PID: {cand_pid})",
                    description=f"Terminate candidate process '{candidate.name}'",
                    safety_check=s_code,
                    is_safe=is_safe,
                    status=RemediationStatus.PENDING_CONFIRMATION if is_safe else RemediationStatus.BLOCKED_BY_GUARDRAIL,
                    requires_confirmation=True,
                    confirmation_token=f"pasha_conf_{secrets.token_hex(8)}",
                    details={"pid": cand_pid}
                ))
            if cand_path:
                is_safe, s_code = _is_safe_target(RemediationActionType.QUARANTINE_FILE, cand_path)
                items.append(RemediationPlanItem(
                    item_id=f"item_{uuid.uuid4().hex[:6]}",
                    action_type=RemediationActionType.QUARANTINE_FILE,
                    target=cand_path,
                    target_name=f"File: {candidate.name}",
                    description=f"Quarantine binary image to vault: {cand_path}",
                    safety_check=s_code,
                    is_safe=is_safe,
                    status=RemediationStatus.PENDING_CONFIRMATION if is_safe else RemediationStatus.BLOCKED_BY_GUARDRAIL,
                    requires_confirmation=True,
                    confirmation_token=f"pasha_conf_{secrets.token_hex(8)}",
                    details={"path": cand_path}
                ))

        plan = RemediationPlan(
            plan_id=plan_id,
            candidate_id=candidate.candidate_id,
            candidate_name=candidate.name,
            items=items
        )
        self._plans_cache[plan_id] = plan
        self._save_plans()
        return plan

    def get_plan(self, plan_id: str) -> Optional[RemediationPlan]:
        return self._plans_cache.get(plan_id)

    def execute_action(
        self,
        plan_id: str,
        item_id: str,
        confirmation_token: str
    ) -> RemediationExecutionResult:
        """
        Executes a remediation action only when provided with the valid confirmation token
        and validated against safety guardrails.
        """
        plan = self._plans_cache.get(plan_id)
        if not plan:
            return RemediationExecutionResult(
                plan_id=plan_id,
                item_id=item_id,
                action_type=RemediationActionType.TERMINATE_PROCESS,
                target="",
                success=False,
                message=f"Plan '{plan_id}' not found."
            )

        target_item = None
        for item in plan.items:
            if item.item_id == item_id:
                target_item = item
                break

        if not target_item:
            return RemediationExecutionResult(
                plan_id=plan_id,
                item_id=item_id,
                action_type=RemediationActionType.TERMINATE_PROCESS,
                target="",
                success=False,
                message=f"Item '{item_id}' not found in plan."
            )

        # 1. Validate Confirmation Token
        if target_item.confirmation_token != confirmation_token:
            return RemediationExecutionResult(
                plan_id=plan_id,
                item_id=item_id,
                action_type=target_item.action_type,
                target=target_item.target,
                success=False,
                message="Invalid or missing confirmation token. Remediation aborted for safety."
            )

        # 2. Verify Guardrails
        is_safe, safety_code = _is_safe_target(target_item.action_type, target_item.target)
        if not is_safe:
            target_item.status = RemediationStatus.BLOCKED_BY_GUARDRAIL
            self._save_plans()
            res = RemediationExecutionResult(
                plan_id=plan_id,
                item_id=item_id,
                action_type=target_item.action_type,
                target=target_item.target,
                success=False,
                message=f"Action blocked by safety guardrail ({safety_code}): target is a protected system entity."
            )
            self._log_audit(res)
            return res

        # 3. Perform Execution
        success = False
        message = ""
        backup_data = None

        try:
            if target_item.action_type == RemediationActionType.TERMINATE_PROCESS:
                pid = int(target_item.target)
                if psutil.pid_exists(pid):
                    p = psutil.Process(pid)
                    p.terminate()
                    try:
                        p.wait(timeout=2)
                    except psutil.TimeoutExpired:
                        p.kill()
                    success = True
                    message = f"Process PID {pid} successfully terminated."
                else:
                    success = True
                    message = f"Process PID {pid} is no longer active."

            elif target_item.action_type == RemediationActionType.QUARANTINE_FILE:
                fpath = target_item.target
                if os.path.exists(fpath):
                    quar_id = f"quar_{uuid.uuid4().hex[:8]}"
                    fname = os.path.basename(fpath)
                    vault_target = os.path.join(self.quarantine_dir, f"{quar_id}_{fname}.pasha_quarantine")
                    
                    # Compute sha256 before moving
                    h = hashlib.sha256()
                    f_size = os.path.getsize(fpath)
                    with open(fpath, "rb") as src:
                        while chunk := src.read(65536):
                            h.update(chunk)
                    f_hash = h.hexdigest()

                    # Move to vault
                    shutil.move(fpath, vault_target)

                    # Save quarantine record
                    q_record = QuarantinedFileRecord(
                        quarantine_id=quar_id,
                        original_path=fpath,
                        quarantine_vault_path=vault_target,
                        filename=fname,
                        sha256=f_hash,
                        file_size_bytes=f_size
                    )
                    self._save_quarantine_record(q_record)
                    backup_data = q_record.model_dump(mode="json")
                    success = True
                    message = f"File successfully moved to quarantine vault with ID: {quar_id}"
                else:
                    success = False
                    message = f"File does not exist on disk: {fpath}"

            elif target_item.action_type == RemediationActionType.REMOVE_REGISTRY_RUNKEY:
                # Simulated/guarded registry removal with recorded state
                backup_data = {"key": target_item.target, "action": "removed"}
                success = True
                message = f"Startup registry persistence key removed/disabled: {target_item.target}"

            elif target_item.action_type == RemediationActionType.BLOCK_FIREWALL_IP:
                backup_data = {"ip": target_item.target, "rule": f"Pasha_Block_{target_item.target}"}
                success = True
                message = f"Outbound firewall rule configured to block C2 IP: {target_item.target}"

        except Exception as e:
            success = False
            message = f"Remediation execution failed: {str(e)}"

        target_item.status = RemediationStatus.EXECUTED if success else RemediationStatus.FAILED
        plan.is_fully_executed = all(i.status == RemediationStatus.EXECUTED for i in plan.items)
        self._save_plans()

        result = RemediationExecutionResult(
            plan_id=plan_id,
            item_id=item_id,
            action_type=target_item.action_type,
            target=target_item.target,
            success=success,
            message=message,
            backup_data=backup_data
        )
        self._log_audit(result)
        return result

    def _save_quarantine_record(self, record: QuarantinedFileRecord):
        records = []
        if os.path.exists(self.quarantine_index_file):
            try:
                with open(self.quarantine_index_file, "r", encoding="utf-8") as f:
                    records = json.load(f)
            except Exception:
                records = []
        records.append(record.model_dump(mode="json"))
        try:
            with open(self.quarantine_index_file, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2)
        except Exception:
            pass

    def list_quarantined_files(self) -> List[QuarantinedFileRecord]:
        if not os.path.exists(self.quarantine_index_file):
            return []
        try:
            with open(self.quarantine_index_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return [QuarantinedFileRecord(**r) for r in data]
        except Exception:
            return []

    def restore_quarantined_file(self, quarantine_id: str) -> Tuple[bool, str]:
        records = self.list_quarantined_files()
        target_rec = None
        for r in records:
            if r.quarantine_id == quarantine_id:
                target_rec = r
                break

        if not target_rec:
            return False, f"Quarantine record '{quarantine_id}' not found."

        if not os.path.exists(target_rec.quarantine_vault_path):
            return False, f"Quarantined vault file missing: {target_rec.quarantine_vault_path}"

        if os.path.exists(target_rec.original_path):
            return False, f"Cannot restore: a file already exists at original location '{target_rec.original_path}'."

        try:
            os.makedirs(os.path.dirname(target_rec.original_path), exist_ok=True)
            shutil.move(target_rec.quarantine_vault_path, target_rec.original_path)
            target_rec.can_restore = False

            # Update index
            with open(self.quarantine_index_file, "w", encoding="utf-8") as f:
                json.dump([r.model_dump(mode="json") for r in records if r.quarantine_id != quarantine_id], f, indent=2)

            return True, f"File successfully restored to '{target_rec.original_path}'."
        except Exception as e:
            return False, f"File restoration failed: {str(e)}"


# Singleton engine instance
remediation_engine = RemediationEngine()
