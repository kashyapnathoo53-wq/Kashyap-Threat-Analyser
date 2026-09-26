from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class AffectedEntity(BaseModel):
    """
    A specific host entity touched, modified, or communicated with by the threat.
    """
    entity_type: str  # 'process', 'file', 'registry', 'network', 'account'
    identifier: str   # PID, file path, registry key, IP:port
    name: str         # Human-friendly display label
    impact_type: str  # 'SPAWNED', 'INJECTED', 'DROPPED', 'MODIFIED', 'PERSISTED', 'BEACONED'
    severity: str = "MEDIUM"  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    details: Dict[str, Any] = Field(default_factory=dict)


class ContainmentAction(BaseModel):
    """
    Recommended, deterministic containment action to isolate or remediate the entity.
    """
    action_id: str
    target_type: str  # 'process', 'file', 'registry', 'network'
    target: str       # PID, path, registry key, IP address
    action: str       # 'TERMINATE', 'QUARANTINE', 'DELETE_KEY', 'BLOCK_FIREWALL'
    description: str
    urgency: str = "HIGH"  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'


class BlastRadiusReport(BaseModel):
    """
    Comprehensive Impact and Blast Radius Report mapping total footprint
    and containment boundaries across the host.
    """
    report_id: str
    candidate_id: str
    candidate_name: str
    scope_level: str  # 'CONTAINED', 'LOCAL_SURFACE', 'PERSISTED', 'HOST_WIDE_COMPROMISE'
    blast_score: int = Field(ge=0, le=100)  # 0 to 100 impact index
    total_affected_entities: int = 0
    affected_processes: List[AffectedEntity] = Field(default_factory=list)
    affected_files: List[AffectedEntity] = Field(default_factory=list)
    affected_registry: List[AffectedEntity] = Field(default_factory=list)
    affected_network: List[AffectedEntity] = Field(default_factory=list)
    summary_narrative: str
    containment_actions: List[ContainmentAction] = Field(default_factory=list)
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
