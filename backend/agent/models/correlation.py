from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class EvidenceNode(BaseModel):
    id: str
    type: str  # "process", "file", "persistence", "network", "yara", "ioc", "mitre"
    label: str
    severity: str = "INFO"  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    timestamp: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class EvidenceEdge(BaseModel):
    source: str
    target: str
    relation: str  # "SPAWNED", "DROPPED", "PERSISTED_VIA", "BEACONED_TO", "MATCHED_RULE", "ATTRIBUTED_TO"
    label: str
    confidence: float = 1.0


class AttackStoryPhase(BaseModel):
    phase_name: str  # e.g. "Initial Discovery", "Execution & Defense Evasion", "Persistence", "Command & Control"
    tactic: Optional[str] = None
    narrative: str
    node_ids: List[str] = Field(default_factory=list)


class AttackStoryGraph(BaseModel):
    nodes: List[EvidenceNode] = Field(default_factory=list)
    edges: List[EvidenceEdge] = Field(default_factory=list)


class AttackStory(BaseModel):
    story_id: str
    candidate_id: str
    report_id: Optional[str] = None
    snapshot_id: Optional[str] = None
    title: str
    verdict: str  # "MALICIOUS", "SUSPICIOUS", "BENIGN", "LOW RISK"
    threat_score: int = 0
    confidence_score: int = 85  # 0 to 100%
    summary_narrative: str
    phases: List[AttackStoryPhase] = Field(default_factory=list)
    graph: AttackStoryGraph = Field(default_factory=AttackStoryGraph)
    root_cause_node_id: Optional[str] = None
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
