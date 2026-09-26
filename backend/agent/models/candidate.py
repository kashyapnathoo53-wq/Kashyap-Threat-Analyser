from enum import Enum
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class CandidateStatus(str, Enum):
    DISCOVERED = "DISCOVERED"
    QUEUED = "QUEUED"
    ANALYZING = "ANALYZING"
    ANALYZED = "ANALYZED"
    IGNORED = "IGNORED"


class SuspiciousCandidate(BaseModel):
    candidate_id: str
    snapshot_id: str
    category: str  # "process", "file", "persistence", "service", "scheduled_task", "network"
    name: str
    target_path: Optional[str] = None
    cmdline: Optional[str] = None
    sha256: Optional[str] = None
    size_bytes: Optional[int] = None
    discovery_source: str = "snapshot_collector"  # "snapshot_collector" or "security_diff"
    heuristics_matched: List[str] = Field(default_factory=list)
    priority_score: int = Field(default=50, ge=0, le=100)  # 0 to 100
    status: CandidateStatus = CandidateStatus.DISCOVERED
    discovered_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    analysis_report_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CandidateQueueSummary(BaseModel):
    total_candidates: int = 0
    by_status: Dict[str, int] = Field(default_factory=dict)
    by_category: Dict[str, int] = Field(default_factory=dict)
    highest_priority_score: int = 0
    top_candidates: List[SuspiciousCandidate] = Field(default_factory=list)
