from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone

class DiffItem(BaseModel):
    change_type: str  # "ADDED", "REMOVED", "MODIFIED"
    category: str     # "process", "persistence", "service", "scheduled_task", "network", "file", "browser"
    identifier: str   # Primary key or human readable identification
    name: str         # Item name
    details: Dict[str, Any] = Field(default_factory=dict)
    base_value: Optional[Dict[str, Any]] = None
    target_value: Optional[Dict[str, Any]] = None
    is_security_relevant: bool = False
    risk_level: str = "INFO"  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    reasons: List[str] = Field(default_factory=list)


class CategoryDiff(BaseModel):
    category: str
    added_count: int = 0
    removed_count: int = 0
    modified_count: int = 0
    security_relevant_count: int = 0
    items: List[DiffItem] = Field(default_factory=list)


class SecurityDiffResult(BaseModel):
    diff_id: str
    base_snapshot_id: Optional[str] = None
    target_snapshot_id: str
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    base_timestamp: Optional[str] = None
    target_timestamp: str = ""
    time_delta_seconds: Optional[float] = None
    summary: Dict[str, Any] = Field(default_factory=dict)
    categories: Dict[str, CategoryDiff] = Field(default_factory=dict)
    security_relevant_changes: List[DiffItem] = Field(default_factory=list)
