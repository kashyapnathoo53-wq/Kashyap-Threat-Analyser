from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field


class TimelineEvent(BaseModel):
    """
    An individual chronological security event extracted from host telemetry,
    security diffs, or sandbox emulation.
    """
    event_id: str
    timestamp: str  # ISO-8601 formatted timestamp string
    relative_time_seconds: float = 0.0  # Seconds relative to timeline anchor (T0 = 0.0)
    category: str   # 'process', 'filesystem', 'persistence', 'network', 'api_call', 'detection', 'mitre'
    severity: str = "INFO"  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    source: str     # 'host_snapshot', 'security_diff', 'behavioral_sandbox', 'candidate_detector', 'mitre_mapper'
    title: str      # Concise event summary (e.g. "Process Started: powershell.exe")
    description: str# Detailed context (e.g. "Executed with arguments -Enc ... by parent PID 2100")
    details: Dict[str, Any] = Field(default_factory=dict)  # Technical attributes (pid, path, port, etc.)
    related_indicators: List[str] = Field(default_factory=list)  # Associated IPs, hashes, paths


class SecurityTimeline(BaseModel):
    """
    Comprehensive forensic timeline reconstructing the observed attack sequence
    across host activities and sandbox behavioral execution.
    """
    timeline_id: str
    target_id: str          # candidate_id, snapshot_id, or "host_latest"
    target_type: str        # 'candidate', 'snapshot', 'global'
    generated_at: str
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    total_events: int = 0
    event_counts_by_category: Dict[str, int] = Field(default_factory=dict)
    event_counts_by_severity: Dict[str, int] = Field(default_factory=dict)
    events: List[TimelineEvent] = Field(default_factory=list)
