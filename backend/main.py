import os
from typing import Dict, List, Any, Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response, JSONResponse
from pydantic import BaseModel

from static_analyzer import StaticAnalyzer
from yara_engine import YaraEngine
from behavioral_emulator import BehavioralEmulator
from ioc_extractor import IocExtractor
from mitre_mapper import MitreMapper
from threat_scorer import ThreatScorer
from reporter import Reporter
from samples_generator import get_preset_samples, get_preset_sample_by_id
from host_scanner import HostScanner
from ai_assistant import ai_assistant

from agent.main import run_local_scan, AGENT_VERSION, get_machine_id
from agent.storage.snapshot_store import SnapshotStore
from agent.models.candidate import SuspiciousCandidate, CandidateStatus, CandidateQueueSummary
from agent.storage.candidate_queue import CandidateQueue
from agent.security.candidate_detector import (
    detect_candidates_from_snapshot,
    detect_candidates_from_diff
)
from agent.orchestration.investigator import InvestigationOrchestrator
from agent.security.correlation import correlate_evidence
from agent.security.timeline import reconstruct_security_timeline
from agent.security.blast_radius import compute_blast_radius
from agent.security.metrics import evaluate_dual_metrics



app = FastAPI(
    title="Pasha - Automated Malware Static & Behavioral Analysis Platform",
    description="Full Threat Scoring, IOC Extraction, MITRE ATT&CK Mapping, YARA Engine & Reporting",
    version="2.0.0"
)

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize analytical core engines
static_analyzer = StaticAnalyzer()
yara_engine = YaraEngine()
behavioral_emulator = BehavioralEmulator()
ioc_extractor = IocExtractor()
mitre_mapper = MitreMapper()
threat_scorer = ThreatScorer()
reporter = Reporter()
host_scanner = HostScanner()
snapshot_store = SnapshotStore()
candidate_queue = CandidateQueue()


# Global memory storage for analyzed reports
analysis_store: Dict[str, Any] = {}
latest_host_assessment: Dict[str, Any] = {}

class CustomYaraRequest(BaseModel):
    name: str
    category: str
    strings: List[str]
    condition: str

class PresetAnalyzeRequest(BaseModel):
    sample_id: str

class RoadmapRequest(BaseModel):
    report: Optional[Dict[str, Any]] = None
    host_assessment: Optional[Dict[str, Any]] = None

class JarvisChatRequest(BaseModel):
    message: str
    report: Optional[Dict[str, Any]] = None
    host_assessment: Optional[Dict[str, Any]] = None
    history: Optional[List[Dict[str, str]]] = None

class AgentScanRequest(BaseModel):
    save_to_store: bool = True
    max_snapshots: int = 50

class AgentPruneRequest(BaseModel):
    max_snapshots: Optional[int] = 30
    max_age_days: Optional[int] = 30

class CandidateDetectRequest(BaseModel):
    snapshot_id: Optional[str] = None
    diff_id: Optional[str] = None
    auto_queue: bool = True

class CandidateStatusUpdateRequest(BaseModel):
    status: str
    analysis_report_id: Optional[str] = None



@app.get("/")
def root():
    return {"status": "online", "platform": "Pasha v2.0"}

@app.get("/api/health")
def health():
    return {"status": "ok", "engines": ["static", "yara", "behavioral", "ioc", "mitre", "scorer", "reporter", "host_scanner"]}

@app.get("/api/system/auto-assess")
def get_system_auto_assess():
    global latest_host_assessment
    result = host_scanner.auto_assess_system()
    latest_host_assessment = result
    return result

@app.get("/api/system/quick-status")
def get_system_quick_status():
    global latest_host_assessment
    if not latest_host_assessment:
        latest_host_assessment = host_scanner.auto_assess_system()
    return {
        "status": latest_host_assessment.get("status", "HEALTHY / PROTECTED"),
        "health_score": latest_host_assessment.get("health_score", 100),
        "status_color": latest_host_assessment.get("status_color", "#22c55e"),
        "alert_level": latest_host_assessment.get("alert_level", "INFO"),
        "suspicious_processes": latest_host_assessment.get("summary", {}).get("suspicious_processes", 0),
        "vulnerabilities": latest_host_assessment.get("summary", {}).get("known_vulnerabilities_detected", 0)
    }

@app.get("/api/samples/presets")
def list_presets():
    return get_preset_samples()

@app.post("/api/ai/eradication-roadmap")
def get_eradication_roadmap(req: RoadmapRequest):
    return ai_assistant.generate_eradication_roadmap(req.report, req.host_assessment)

@app.post("/api/jarvis/chat")
def chat_with_jarvis(req: JarvisChatRequest):
    reply = ai_assistant.chat(req.message, req.report, req.host_assessment, req.history)
    return {"reply": reply}

# ==========================================
# PASHA 2.0 LOCAL AGENT & SNAPSHOT ENDPOINTS
# ==========================================

@app.get("/api/agent/status")
def get_agent_status():
    """Returns local agent operational status, machine ID, and snapshot storage metrics."""
    stats = snapshot_store.get_storage_stats()
    return {
        "status": "online",
        "agent_version": AGENT_VERSION,
        "machine_id": get_machine_id(),
        "storage": stats
    }

@app.get("/api/agent/snapshots")
def list_agent_snapshots(limit: Optional[int] = 50, offset: int = 0):
    """Lists recorded security snapshots in reverse chronological order."""
    snaps = snapshot_store.list_snapshots(limit=limit, offset=offset)
    stats = snapshot_store.get_storage_stats()
    return {
        "total": stats["total_snapshots"],
        "limit": limit,
        "offset": offset,
        "snapshots": snaps
    }

@app.get("/api/agent/snapshots/latest")
def get_latest_agent_snapshot():
    """Retrieves the most recent security snapshot."""
    snap = snapshot_store.get_latest_snapshot()
    if not snap:
        raise HTTPException(status_code=404, detail="No security snapshots recorded yet.")
    res = snap.model_dump(by_alias=False)
    res["collector_reports"] = res.get("collectors_executed", {})
    res["persistence"] = res.get("persistence_items", [])
    res["network"] = res.get("network_connections", [])
    res["files"] = res.get("scanned_files", [])
    res["browser"] = res.get("browser_info", [])
    return res

@app.get("/api/agent/snapshots/{snapshot_id}")
def get_agent_snapshot(snapshot_id: str):
    """Retrieves a specific security snapshot by snapshot_id."""
    snap = snapshot_store.load_snapshot(snapshot_id)
    if not snap:
        raise HTTPException(status_code=404, detail=f"Snapshot '{snapshot_id}' not found.")
    res = snap.model_dump(by_alias=False)
    res["collector_reports"] = res.get("collectors_executed", {})
    res["persistence"] = res.get("persistence_items", [])
    res["network"] = res.get("network_connections", [])
    res["files"] = res.get("scanned_files", [])
    res["browser"] = res.get("browser_info", [])
    return res

@app.post("/api/agent/scan")
def trigger_agent_scan(req: Optional[AgentScanRequest] = None):
    """Executes a fresh read-only Windows security scan and returns the snapshot."""
    save = req.save_to_store if req else True
    snap = run_local_scan(save_to_store=save)
    res = snap.model_dump(by_alias=False)
    res["collector_reports"] = res.get("collectors_executed", {})
    res["persistence"] = res.get("persistence_items", [])
    res["network"] = res.get("network_connections", [])
    res["files"] = res.get("scanned_files", [])
    res["browser"] = res.get("browser_info", [])
    return res

@app.delete("/api/agent/snapshots/{snapshot_id}")
def delete_agent_snapshot(snapshot_id: str):
    """Safely deletes a snapshot from disk storage."""
    deleted = snapshot_store.delete_snapshot(snapshot_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Snapshot '{snapshot_id}' not found or could not be deleted.")
    return {"status": "deleted", "snapshot_id": snapshot_id}

@app.post("/api/agent/snapshots/prune")
def prune_agent_snapshots(req: AgentPruneRequest):
    """Enforces retention policy by removing old or excess snapshots."""
    result = snapshot_store.prune_snapshots(max_snapshots=req.max_snapshots, max_age_days=req.max_age_days)
    return {"status": "success", "result": result}

@app.get("/api/agent/diff")
def get_agent_diff(base_id: Optional[str] = None, target_id: Optional[str] = None):
    """
    Computes structural security diff between target snapshot and base snapshot.
    If target_id is omitted, defaults to latest snapshot.
    If base_id is omitted, automatically resolves to predecessor snapshot.
    """
    all_snaps = snapshot_store.list_snapshots()
    if not all_snaps:
        raise HTTPException(status_code=404, detail="No snapshots available for diff.")

    # Resolve target
    if not target_id:
        target_id = all_snaps[0]["snapshot_id"]

    target_snap = snapshot_store.load_snapshot(target_id)
    if not target_snap:
        raise HTTPException(status_code=404, detail=f"Target snapshot '{target_id}' not found.")

    # Resolve base
    base_snap = None
    if base_id:
        base_snap = snapshot_store.load_snapshot(base_id)
        if not base_snap:
            raise HTTPException(status_code=404, detail=f"Base snapshot '{base_id}' not found.")
    else:
        # Auto-find predecessor (the snapshot created right before target_id)
        target_index = -1
        for i, s in enumerate(all_snaps):
            if s["snapshot_id"] == target_snap.snapshot_id:
                target_index = i
                break
        if target_index >= 0 and target_index + 1 < len(all_snaps):
            pred_id = all_snaps[target_index + 1]["snapshot_id"]
            base_snap = snapshot_store.load_snapshot(pred_id)

    from agent.security.diff import compute_security_diff
    diff_res = compute_security_diff(target_snap, base_snap)
    return diff_res.model_dump()

@app.get("/api/agent/diff/latest")
def get_latest_agent_diff():
    """
    Convenience endpoint comparing the most recent snapshot against its predecessor.
    """
    res = snapshot_store.diff_latest_against_previous()
    if not res:
        raise HTTPException(status_code=404, detail="No snapshots available for diff.")
    return res.model_dump()

# ==========================================
# PASHA 2.0 CANDIDATE DETECTION & QUEUE APIS
# ==========================================

@app.get("/api/agent/candidates")
def list_candidates(
    status: Optional[str] = None,
    category: Optional[str] = None,
    limit: Optional[int] = 50,
    offset: int = 0
):
    """
    Lists prioritized suspicious candidates with optional status/category filters.
    """
    items = candidate_queue.list_candidates(status=status, category=category, limit=limit, offset=offset)
    summary = candidate_queue.get_summary()
    return {
        "total": summary.total_candidates,
        "returned": len(items),
        "limit": limit,
        "offset": offset,
        "candidates": [c.model_dump(mode="json") for c in items]
    }

@app.get("/api/agent/candidates/summary")
def get_candidate_queue_summary():
    """
    Returns aggregated metrics for the candidate queue (counts by status, counts by category, top candidates).
    """
    return candidate_queue.get_summary().model_dump(mode="json")

@app.get("/api/agent/candidates/next")
def get_next_candidate_for_analysis():
    """
    Pulls the next highest-priority candidate ready for deep investigation.
    """
    cand = candidate_queue.get_next_queued_candidate()
    if not cand:
        raise HTTPException(status_code=404, detail="No pending candidates waiting in investigation queue.")
    return cand.model_dump(mode="json")

@app.get("/api/agent/candidates/{candidate_id}")
def get_candidate_by_id(candidate_id: str):
    """
    Retrieves full metadata for a specific candidate.
    """
    cand = candidate_queue.get_candidate(candidate_id)
    if not cand:
        raise HTTPException(status_code=404, detail=f"Candidate '{candidate_id}' not found.")
    return cand.model_dump(mode="json")

@app.post("/api/agent/candidates/detect")
def trigger_candidate_detection(req: Optional[CandidateDetectRequest] = None):
    """
    Executes candidate detection across a snapshot or security diff and enqueues newly discovered threats.
    If no snapshot_id or diff_id provided, automatically scans the latest snapshot and diff!
    """
    auto_queue = req.auto_queue if req else True
    discovered: List[SuspiciousCandidate] = []

    # Case 1: Specific snapshot requested
    if req and req.snapshot_id:
        snap = snapshot_store.load_snapshot(req.snapshot_id)
        if not snap:
            raise HTTPException(status_code=404, detail=f"Snapshot '{req.snapshot_id}' not found.")
        discovered.extend(detect_candidates_from_snapshot(snap))
    # Case 2: Default — detect from latest snapshot and latest diff
    else:
        latest_snap = snapshot_store.get_latest_snapshot()
        if latest_snap:
            # Detect from snapshot
            snap_cands = detect_candidates_from_snapshot(latest_snap)
            discovered.extend(snap_cands)

            # Detect from latest diff
            latest_diff = snapshot_store.diff_latest_against_previous()
            if latest_diff:
                diff_cands = detect_candidates_from_diff(latest_diff, latest_snap)
                discovered.extend(diff_cands)

    if auto_queue:
        for c in discovered:
            if c.status == CandidateStatus.DISCOVERED:
                c.status = CandidateStatus.QUEUED

    enqueued = candidate_queue.add_candidates(discovered)
    return {
        "status": "success",
        "detected_count": len(discovered),
        "enqueued_count": len(enqueued),
        "candidates": [c.model_dump(mode="json") for c in enqueued]
    }

@app.patch("/api/agent/candidates/{candidate_id}/status")
def update_candidate_status(candidate_id: str, req: CandidateStatusUpdateRequest):
    """
    Updates the lifecycle status of a candidate (DISCOVERED, QUEUED, ANALYZING, ANALYZED, IGNORED).
    """
    updated = candidate_queue.update_status(candidate_id, req.status, req.analysis_report_id)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Candidate '{candidate_id}' not found.")
    return {"status": "success", "candidate": updated.model_dump(mode="json")}

@app.delete("/api/agent/candidates/{candidate_id}")
def delete_candidate_from_queue(candidate_id: str):
    """
    Removes a candidate from the queue.
    """
    deleted = candidate_queue.delete_candidate(candidate_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Candidate '{candidate_id}' not found.")
    return {"status": "deleted", "candidate_id": candidate_id}




def run_full_analysis(filename: str, content: bytes) -> Dict[str, Any]:
    import time
    start_time = time.time()
    file_info = {"filename": filename}
    
    # 1. Static Analysis
    static_res = static_analyzer.analyze(content, filename)
    
    # 2. YARA Rule Scan
    yara_res = yara_engine.scan(content)
    
    # 3. Behavioral Sandbox Emulation
    behavioral_res = behavioral_emulator.emulate_execution(content, file_info, static_res)
    
    # 4. IOC Extraction
    ioc_res = ioc_extractor.extract(content, static_res, behavioral_res)
    
    # 5. MITRE ATT&CK Mapping
    mitre_res = mitre_mapper.map_analysis(static_res, yara_res, behavioral_res, ioc_res)
    
    # 6. Threat Risk Scoring
    threat_res = threat_scorer.calculate_score(static_res, yara_res, behavioral_res, ioc_res, mitre_res)

    report_id = static_res["hashes"]["sha256"]
    duration_ms = round((time.time() - start_time) * 1000, 2)

    result = {
        "report_id": report_id,
        "sample_name": filename,
        "timestamp": "2026-09-18T16:00:00Z",
        "analysis_duration_ms": duration_ms,
        "file_size_bytes": len(content),
        "static_analysis": static_res,
        "yara_scan": yara_res,
        "behavioral_analysis": behavioral_res,
        "ioc_extraction": ioc_res,
        "mitre_mapping": mitre_res,
        "threat_scoring": threat_res
    }

    # Store report in memory store
    analysis_store[report_id] = result
    return result

# Initialize investigation orchestrator using analytical core
orchestrator = InvestigationOrchestrator(
    candidate_queue=candidate_queue,
    analysis_fn=run_full_analysis,
    analysis_store=analysis_store
)

# ==========================================
# PASHA 2.0 INVESTIGATION ORCHESTRATION APIS
# ==========================================

@app.post("/api/agent/investigate/next")
def investigate_next_endpoint():
    """
    Pulls and executes deep analysis on the highest-priority pending candidate in the queue.
    """
    res = orchestrator.investigate_next()
    if not res:
        raise HTTPException(status_code=404, detail="No pending candidates waiting in queue.")
    return res

@app.post("/api/agent/investigate/batch")
def investigate_batch_endpoint(count: int = 3):
    """
    Sequentially investigates the next N prioritized candidates in the queue.
    """
    results = orchestrator.investigate_batch(max_count=count)
    return {
        "status": "success",
        "investigated_count": len(results),
        "results": results
    }

@app.post("/api/agent/investigate/{candidate_id}")
def investigate_candidate_endpoint(candidate_id: str):
    """
    Triggers automated deep analysis (Static, YARA, Behavioral, IOC, MITRE) for a candidate.
    """
    res = orchestrator.investigate_candidate(candidate_id)
    if not res:
        raise HTTPException(status_code=404, detail=f"Candidate '{candidate_id}' not found.")
    return res


@app.get("/api/agent/candidates/{candidate_id}/report")
def get_candidate_analysis_report(candidate_id: str):
    """
    Retrieves the full analysis report linked to a specific candidate.
    """
    report = orchestrator.get_candidate_report(candidate_id)
    if not report:
        cand = candidate_queue.get_candidate(candidate_id)
        if not cand:
            raise HTTPException(status_code=404, detail=f"Candidate '{candidate_id}' not found.")
        raise HTTPException(status_code=404, detail=f"Candidate '{candidate_id}' has not been analyzed yet (Status: {cand.status}).")
    return report

# ==========================================
# PASHA 2.0 EVIDENCE CORRELATION & ATTACK STORY
# ==========================================

@app.get("/api/agent/attack-story/latest")
def get_latest_attack_story():
    """
    Constructs the correlated Attack Story and Evidence Graph for the latest investigated candidate.
    """
    # 1. Prefer analyzed candidates
    candidates = candidate_queue.list_candidates(status="ANALYZED", limit=1)
    if not candidates:
        # Fallback to highest priority candidate in queue
        candidates = candidate_queue.list_candidates(limit=1)
    if not candidates:
        raise HTTPException(status_code=404, detail="No candidates found to build Attack Story.")

    cand = candidates[0]
    report = orchestrator.get_candidate_report(cand.candidate_id)
    snapshot = snapshot_store.load_snapshot(cand.snapshot_id) if cand.snapshot_id else None

    story = correlate_evidence(candidate=cand, report=report, snapshot=snapshot)
    return story.model_dump(mode="json")

@app.get("/api/agent/attack-story/{candidate_id}")
def get_candidate_attack_story(candidate_id: str):
    """
    Constructs the correlated Attack Story and Evidence Graph for a specific candidate.
    """
    cand = candidate_queue.get_candidate(candidate_id)
    if not cand:
        raise HTTPException(status_code=404, detail=f"Candidate '{candidate_id}' not found.")

    report = orchestrator.get_candidate_report(candidate_id)
    snapshot = snapshot_store.load_snapshot(cand.snapshot_id) if cand.snapshot_id else None

    story = correlate_evidence(candidate=cand, report=report, snapshot=snapshot)
    return story.model_dump(mode="json")


# -------------------------------------------------------------
# MILESTONE 7: SECURITY TIMELINE RECONSTRUCTION
# -------------------------------------------------------------

@app.get("/api/agent/timeline/latest")
def get_latest_security_timeline():
    """
    Reconstructs the chronological forensic timeline for the latest investigated candidate
    or most recent host snapshot.
    """
    candidates = candidate_queue.list_candidates(status="ANALYZED", limit=1)
    if not candidates:
        candidates = candidate_queue.list_candidates(limit=1)

    if candidates:
        cand = candidates[0]
        report = orchestrator.get_candidate_report(cand.candidate_id)
        snapshot = snapshot_store.load_snapshot(cand.snapshot_id) if cand.snapshot_id else None
        timeline = reconstruct_security_timeline(candidate=cand, report=report, snapshot=snapshot)
        return timeline.model_dump(mode="json")

    # If no candidate, fallback to latest host snapshot
    snap = snapshot_store.get_latest_snapshot()
    if not snap:
        raise HTTPException(status_code=404, detail="No candidates or snapshots found to construct timeline.")

    timeline = reconstruct_security_timeline(snapshot=snap)
    return timeline.model_dump(mode="json")


@app.get("/api/agent/timeline/snapshot/{snapshot_id}")
def get_snapshot_security_timeline(snapshot_id: str):
    """
    Reconstructs the forensic timeline across all events in a specific host snapshot.
    """
    snap = snapshot_store.load_snapshot(snapshot_id)
    if not snap:
        raise HTTPException(status_code=404, detail=f"Snapshot '{snapshot_id}' not found.")

    timeline = reconstruct_security_timeline(snapshot=snap)
    return timeline.model_dump(mode="json")


@app.get("/api/agent/timeline/{candidate_id}")
def get_candidate_security_timeline(candidate_id: str):
    """
    Reconstructs the chronological forensic timeline for a specific suspicious candidate.
    """
    cand = candidate_queue.get_candidate(candidate_id)
    if not cand:
        raise HTTPException(status_code=404, detail=f"Candidate '{candidate_id}' not found.")

    report = orchestrator.get_candidate_report(candidate_id)
    snapshot = snapshot_store.load_snapshot(cand.snapshot_id) if cand.snapshot_id else None
    timeline = reconstruct_security_timeline(candidate=cand, report=report, snapshot=snapshot)
    return timeline.model_dump(mode="json")


# -------------------------------------------------------------
# MILESTONE 8: IMPACT & BLAST RADIUS ANALYSIS
# -------------------------------------------------------------

@app.get("/api/agent/blast-radius/latest")
def get_latest_blast_radius():
    """
    Computes the Impact and Blast Radius for the latest investigated candidate.
    """
    candidates = candidate_queue.list_candidates(status="ANALYZED", limit=1)
    if not candidates:
        candidates = candidate_queue.list_candidates(limit=1)

    if not candidates:
        raise HTTPException(status_code=404, detail="No candidates found to evaluate blast radius.")

    cand = candidates[0]
    report = orchestrator.get_candidate_report(cand.candidate_id)
    snapshot = snapshot_store.load_snapshot(cand.snapshot_id) if cand.snapshot_id else None
    blast_report = compute_blast_radius(candidate=cand, report=report, snapshot=snapshot)
    return blast_report.model_dump(mode="json")


@app.get("/api/agent/blast-radius/{candidate_id}")
def get_candidate_blast_radius(candidate_id: str):
    """
    Computes the Impact and Blast Radius for a specific suspicious candidate.
    """
    cand = candidate_queue.get_candidate(candidate_id)
    if not cand:
        raise HTTPException(status_code=404, detail=f"Candidate '{candidate_id}' not found.")

    report = orchestrator.get_candidate_report(candidate_id)
    snapshot = snapshot_store.load_snapshot(cand.snapshot_id) if cand.snapshot_id else None
    blast_report = compute_blast_radius(candidate=cand, report=report, snapshot=snapshot)
    return blast_report.model_dump(mode="json")


# -------------------------------------------------------------
# MILESTONE 9: RISK VS. CONFIDENCE METRIC SEPARATION
# -------------------------------------------------------------

@app.get("/api/agent/metrics/latest")
def get_latest_threat_metrics():
    """
    Evaluates independent Risk Severity and Evidentiary Confidence metrics
    for the latest investigated candidate.
    """
    candidates = candidate_queue.list_candidates(status="ANALYZED", limit=1)
    if not candidates:
        candidates = candidate_queue.list_candidates(limit=1)

    if not candidates:
        raise HTTPException(status_code=404, detail="No candidates found to evaluate threat metrics.")

    cand = candidates[0]
    report = orchestrator.get_candidate_report(cand.candidate_id)
    snapshot = snapshot_store.load_snapshot(cand.snapshot_id) if cand.snapshot_id else None
    metrics = evaluate_dual_metrics(candidate=cand, report=report, snapshot=snapshot)
    return metrics.model_dump(mode="json")


@app.get("/api/agent/metrics/{candidate_id}")
def get_candidate_threat_metrics(candidate_id: str):
    """
    Evaluates independent Risk Severity and Evidentiary Confidence metrics
    for a specific suspicious candidate.
    """
    cand = candidate_queue.get_candidate(candidate_id)
    if not cand:
        raise HTTPException(status_code=404, detail=f"Candidate '{candidate_id}' not found.")

    report = orchestrator.get_candidate_report(candidate_id)
    snapshot = snapshot_store.load_snapshot(cand.snapshot_id) if cand.snapshot_id else None
    metrics = evaluate_dual_metrics(candidate=cand, report=report, snapshot=snapshot)
    return metrics.model_dump(mode="json")


@app.post("/api/analyze/upload")


async def analyze_upload(file: UploadFile = File(...)):
    # Read file content with streaming buffer
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(content) > 104857600:  # 100 MB max guardrail
        raise HTTPException(status_code=413, detail="File size exceeds 100 MB maximum threshold.")
    return run_full_analysis(file.filename, content)

@app.post("/api/analyze/preset")
def analyze_preset(req: PresetAnalyzeRequest):
    preset = get_preset_sample_by_id(req.sample_id)
    return run_full_analysis(preset["name"], preset["content_bytes"])

@app.get("/api/reports/{report_id}")
def get_report(report_id: str):
    if report_id not in analysis_store:
        raise HTTPException(status_code=404, detail="Report ID not found.")
    return analysis_store[report_id]

@app.get("/api/yara/rules")
def get_yara_rules():
    return yara_engine.get_rules()

@app.post("/api/yara/rules")
def add_yara_rule(req: CustomYaraRequest):
    rule = yara_engine.add_custom_rule(req.name, req.category, req.strings, req.condition)
    return {"message": "YARA rule compiled and registered", "rule": rule}

@app.get("/api/reports/{report_id}/export/{format_type}")
def export_report(report_id: str, format_type: str):
    if report_id not in analysis_store:
        # Fallback to default preset if sample not found
        preset = get_preset_sample_by_id("sample_wannacry")
        res = run_full_analysis(preset["name"], preset["content_bytes"])
    else:
        res = analysis_store[report_id]

    sample_name = res["sample_name"]
    s_res = res["static_analysis"]
    t_res = res["threat_scoring"]
    y_res = res["yara_scan"]
    b_res = res["behavioral_analysis"]
    i_res = res["ioc_extraction"]
    m_res = res["mitre_mapping"]

    if format_type == "stix":
        stix_bundle = reporter.generate_stix_21(sample_name, s_res, t_res, i_res, m_res)
        return JSONResponse(content=stix_bundle)
    elif format_type == "misp":
        misp_data = reporter.generate_misp(sample_name, s_res, i_res)
        return JSONResponse(content=misp_data)
    elif format_type == "markdown":
        md = reporter.generate_markdown(sample_name, s_res, t_res, y_res, b_res, i_res, m_res)
        return Response(content=md, media_type="text/markdown")
    elif format_type == "html":
        html = reporter.generate_html(sample_name, s_res, t_res, y_res, b_res, i_res, m_res)
        return HTMLResponse(content=html)
    else:
        raise HTTPException(status_code=400, detail="Invalid export format. Supported: stix, misp, markdown, html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
