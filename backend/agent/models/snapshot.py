from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class ProcessItem(BaseModel):
    pid: int
    name: str
    ppid: Optional[int] = None
    path: Optional[str] = None
    cmdline: Optional[str] = None
    user: Optional[str] = None
    integrity_level: Optional[str] = None
    creation_time: Optional[str] = None
    is_suspicious: bool = False
    suspicious_reasons: List[str] = Field(default_factory=list)


class PersistenceItem(BaseModel):
    name: str
    location: str
    command: str
    file_path: Optional[str] = None
    type: str  # "Registry RunKey", "Startup Folder", "Winlogon"
    is_suspicious: bool = False
    suspicious_reasons: List[str] = Field(default_factory=list)


class ServiceItem(BaseModel):
    name: str
    display_name: Optional[str] = None
    status: str = "UNKNOWN"  # "RUNNING", "STOPPED", "UNKNOWN"
    start_mode: str = "Unknown"  # "Auto", "Manual", "Disabled", "Unknown"
    binary_path: Optional[str] = None
    is_suspicious: bool = False
    suspicious_reasons: List[str] = Field(default_factory=list)


class ScheduledTaskItem(BaseModel):
    name: str
    path: str
    state: str = "Unknown"  # "Ready", "Running", "Disabled", "Unknown"
    action: Optional[str] = None
    author: Optional[str] = None
    is_suspicious: bool = False
    suspicious_reasons: List[str] = Field(default_factory=list)


class NetworkConnectionItem(BaseModel):
    proto: str = "TCP"  # "TCP", "UDP"
    local_addr: str
    local_port: int
    remote_addr: Optional[str] = None
    remote_port: Optional[int] = None
    state: str = "UNKNOWN"
    pid: int
    process_name: Optional[str] = None
    is_suspicious: bool = False
    suspicious_reasons: List[str] = Field(default_factory=list)


class FileItem(BaseModel):
    path: str
    name: str
    size_bytes: int = 0
    category: str  # "Downloads", "Temp", "AppData", "Startup"
    extension: str
    created_time: Optional[str] = None
    modified_time: Optional[str] = None
    sha256: Optional[str] = None
    is_suspicious: bool = False
    suspicious_reasons: List[str] = Field(default_factory=list)


class BrowserInfo(BaseModel):
    name: str
    is_installed: bool = False
    is_default: bool = False
    profile_paths: List[str] = Field(default_factory=list)
    extensions_found: int = 0
    suspicious_extensions: List[str] = Field(default_factory=list)


class CollectorReport(BaseModel):
    collector: str
    status: str = "SUCCESS"  # "SUCCESS", "PARTIAL", "ERROR", "SKIPPED"
    item_count: int = 0
    duration_ms: float = 0.0
    error: Optional[str] = None


class SuspiciousSummaryItem(BaseModel):
    category: str  # "process", "persistence", "service", "scheduled_task", "network", "file"
    name: str
    target: Optional[str] = None
    reasons: List[str] = Field(default_factory=list)
    severity: str = "HIGH"  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    details: Dict[str, Any] = Field(default_factory=dict)


class SecuritySnapshot(BaseModel):
    snapshot_id: str
    schema_version: str = "2.0.0"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    host_id: str = ""
    os_version: str = ""
    system_info: Dict[str, Any] = Field(default_factory=dict)
    summary: Dict[str, Any] = Field(default_factory=dict)
    snapshot_metadata: Dict[str, Any] = Field(default_factory=dict)
    collectors_executed: Dict[str, CollectorReport] = Field(default_factory=dict, alias="collector_reports")
    processes: List[ProcessItem] = Field(default_factory=list)
    persistence_items: List[PersistenceItem] = Field(default_factory=list, alias="persistence")
    services: List[ServiceItem] = Field(default_factory=list)
    scheduled_tasks: List[ScheduledTaskItem] = Field(default_factory=list)
    network_connections: List[NetworkConnectionItem] = Field(default_factory=list, alias="network")
    scanned_files: List[FileItem] = Field(default_factory=list, alias="files")
    browser_info: List[BrowserInfo] = Field(default_factory=list, alias="browser")
    suspicious_items: List[SuspiciousSummaryItem] = Field(default_factory=list)

    # Enable population by field name or alias
    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True
    }

    @property
    def collector_reports(self) -> Dict[str, CollectorReport]:
        return self.collectors_executed

    @property
    def persistence(self) -> List[PersistenceItem]:
        return self.persistence_items

    @property
    def network(self) -> List[NetworkConnectionItem]:
        return self.network_connections

    @property
    def files(self) -> List[FileItem]:
        return self.scanned_files

    @property
    def browser(self) -> List[BrowserInfo]:
        return self.browser_info

