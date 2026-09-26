from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class EvidenceFactor(BaseModel):
    """
    An isolated evidentiary signal contributing independently to Risk and Confidence.
    """
    factor_name: str
    factor_type: str  # 'DETERMINISTIC_SIGNATURE', 'BEHAVIORAL_TELEMETRY', 'HEURISTIC_ANOMALY', 'HOST_CONTEXT'
    weight: float = 1.0
    risk_contribution: int = 0         # 0 to 100 scale impact
    confidence_contribution: int = 0   # 0 to 100 certainty impact
    description: str
    evidence_data: Dict[str, Any] = Field(default_factory=dict)


class DualThreatMetrics(BaseModel):
    """
    Separation of Risk Severity (potential harm) and Evidentiary Confidence (proof certainty).
    """
    metric_id: str
    candidate_id: str
    candidate_name: str
    risk_score: int = Field(ge=0, le=100)          # 0 to 100: How dangerous is this if true?
    confidence_score: int = Field(ge=0, le=100)    # 0 to 100: How conclusive is our evidence?
    risk_tier: str       # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'
    confidence_tier: str # 'CONFIRMED', 'HIGH_CONFIDENCE', 'MODERATE', 'SPECULATIVE'
    action_classification: str  # 'AUTOMATED_CONTAINMENT', 'URGENT_ANALYST_REVIEW', 'SCHEDULED_INVESTIGATION', 'OBSERVE_AND_LOG'
    factors: List[EvidenceFactor] = Field(default_factory=list)
    rationale: str
    computed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
