from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from enum import Enum


class RemediationActionType(str, Enum):
    TERMINATE_PROCESS = "TERMINATE_PROCESS"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    REMOVE_REGISTRY_RUNKEY = "REMOVE_REGISTRY_RUNKEY"
    BLOCK_FIREWALL_IP = "BLOCK_FIREWALL_IP"


class RemediationStatus(str, Enum):
    PENDING_CONFIRMATION = "PENDING_CONFIRMATION"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    BLOCKED_BY_GUARDRAIL = "BLOCKED_BY_GUARDRAIL"
    ROLLED_BACK = "ROLLED_BACK"


class RemediationPlanItem(BaseModel):
    """
    An individual remediation action proposed for local host execution.
    """
    item_id: str
    action_type: RemediationActionType
    target: str          # PID, file path, registry key, or IP address
    target_name: str     # Human-readable title
    description: str
    safety_check: str    # "SAFE", "PROTECTED_SYSTEM_ENTITY", "INVALID_TARGET"
    is_safe: bool = True
    status: RemediationStatus = RemediationStatus.PENDING_CONFIRMATION
    requires_confirmation: bool = True
    confirmation_token: str
    details: Dict[str, Any] = Field(default_factory=dict)


class RemediationPlan(BaseModel):
    """
    Structured, user-confirmed remediation plan covering all identified threat vectors.
    """
    plan_id: str
    candidate_id: str
    candidate_name: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    items: List[RemediationPlanItem] = Field(default_factory=list)
    is_fully_executed: bool = False


class RemediationExecutionResult(BaseModel):
    """
    Audit result of a confirmed remediation action.
    """
    plan_id: str
    item_id: str
    action_type: RemediationActionType
    target: str
    success: bool
    message: str
    executed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    backup_data: Optional[Dict[str, Any]] = None


class QuarantinedFileRecord(BaseModel):
    """
    Metadata tracking a file safely moved into the Pasha quarantine vault.
    """
    quarantine_id: str
    original_path: str
    quarantine_vault_path: str
    filename: str
    sha256: Optional[str] = None
    quarantined_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    file_size_bytes: int = 0
    can_restore: bool = True
