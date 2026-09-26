import os
import sys

# Ensure backend directory is in sys.path if this file is run or imported standalone
_current_dir = os.path.dirname(os.path.abspath(__file__))
_backend_dir = os.path.dirname(os.path.dirname(_current_dir))
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from agent.models.snapshot import (
    ProcessItem,
    PersistenceItem,
    ServiceItem,
    ScheduledTaskItem,
    NetworkConnectionItem,
    FileItem,
    BrowserInfo,
    CollectorReport,
    SecuritySnapshot,
)

from agent.models.timeline import TimelineEvent, SecurityTimeline
from agent.models.blast_radius import AffectedEntity, ContainmentAction, BlastRadiusReport
from agent.models.metrics import EvidenceFactor, DualThreatMetrics
from agent.models.remediation import (
    RemediationActionType,
    RemediationStatus,
    RemediationPlanItem,
    RemediationPlan,
    RemediationExecutionResult,
    QuarantinedFileRecord,
)

__all__ = [
    "ProcessItem",
    "PersistenceItem",
    "ServiceItem",
    "ScheduledTaskItem",
    "NetworkConnectionItem",
    "FileItem",
    "BrowserInfo",
    "CollectorReport",
    "SecuritySnapshot",
    "TimelineEvent",
    "SecurityTimeline",
    "AffectedEntity",
    "ContainmentAction",
    "BlastRadiusReport",
    "EvidenceFactor",
    "DualThreatMetrics",
    "RemediationActionType",
    "RemediationStatus",
    "RemediationPlanItem",
    "RemediationPlan",
    "RemediationExecutionResult",
    "QuarantinedFileRecord",
]

if __name__ == "__main__":
    print("[INFO] 'agent.models' is an internal data model package.")
    print("       To start the Pasha Backend API:  cd backend && python main.py")
    print("       To run the Pasha Local Agent:    python backend/agent/main.py")
    print("       To start the Frontend UI:        cd frontend && npm run dev")
