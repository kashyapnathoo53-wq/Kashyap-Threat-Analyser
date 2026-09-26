import os
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from agent.models.candidate import SuspiciousCandidate
from agent.models.snapshot import SecuritySnapshot
from agent.models.diff import SecurityDiffResult
from agent.models.timeline import TimelineEvent, SecurityTimeline


def _parse_to_epoch(ts_val: Any, fallback_epoch: float = 0.0) -> float:
    """Safely converts string ISO, float, or int to a unix timestamp epoch float."""
    if ts_val is None:
        return fallback_epoch
    if isinstance(ts_val, (int, float)):
        # If it's a relative offset like 1.5, caller should handle anchor addition
        return float(ts_val)
    if isinstance(ts_val, str):
        try:
            # Try ISO parse
            dt = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
            return dt.timestamp()
        except Exception:
            try:
                return float(ts_val)
            except Exception:
                return fallback_epoch
    return fallback_epoch


def reconstruct_security_timeline(
    candidate: Optional[SuspiciousCandidate] = None,
    report: Optional[Dict[str, Any]] = None,
    snapshot: Optional[SecuritySnapshot] = None,
    diff: Optional[SecurityDiffResult] = None
) -> SecurityTimeline:
    """
    Chronologically reconstructs host and sandbox execution events across
    processes, volatile filesystem activity, persistence mechanisms,
    network beacons, behavioral API calls, and MITRE attributions.
    """
    events: List[TimelineEvent] = []
    epoch_map: Dict[str, float] = {}

    # Determine baseline anchor epoch
    anchor_epoch = datetime.now(timezone.utc).timestamp()
    if candidate and candidate.discovered_at:
        anchor_epoch = _parse_to_epoch(candidate.discovered_at, anchor_epoch)
    elif snapshot and snapshot.timestamp:
        anchor_epoch = _parse_to_epoch(snapshot.timestamp, anchor_epoch)

    # -------------------------------------------------------------
    # 1. CANDIDATE IDENTIFICATION EVENT
    # -------------------------------------------------------------
    if candidate:
        cand_epoch = _parse_to_epoch(candidate.discovered_at, anchor_epoch)
        e_cand_id = f"evt_cand_{candidate.candidate_id}"
        cand_sev = "CRITICAL" if candidate.priority_score >= 80 else ("HIGH" if candidate.priority_score >= 60 else ("MEDIUM" if candidate.priority_score >= 40 else "LOW"))
        events.append(TimelineEvent(
            event_id=e_cand_id,
            timestamp=candidate.discovered_at or datetime.fromtimestamp(cand_epoch, tz=timezone.utc).isoformat(),
            category="detection",
            severity=cand_sev,
            source="candidate_detector",
            title=f"Suspicious Candidate Flagged: {candidate.name}",
            description=(
                f"Candidate identified in category '{candidate.category}' with initial priority score "
                f"{candidate.priority_score}/100. Triggers: {', '.join(candidate.heuristics_matched)}."
            ),
            details={
                "candidate_id": candidate.candidate_id,
                "category": candidate.category,
                "score": candidate.priority_score,
                "path": candidate.target_path,
                "sha256": candidate.sha256
            },
            related_indicators=[cand for cand in [candidate.target_path, candidate.sha256] if cand]
        ))
        epoch_map[e_cand_id] = cand_epoch

    # -------------------------------------------------------------
    # 2. HOST PROCESS TELEMETRY (SNAPSHOT / CANDIDATE)
    # -------------------------------------------------------------
    if snapshot and snapshot.processes:
        for p in snapshot.processes:
            p_epoch = _parse_to_epoch(p.creation_time, anchor_epoch - 30.0)
            is_candidate = candidate and (p.name == candidate.name or str(p.pid) in str(candidate.metadata.get("pid", "")))
            
            # Only include candidate processes or high-suspicion processes
            if is_candidate or p.is_suspicious:
                e_id = f"evt_proc_{p.pid}_{uuid.uuid4().hex[:4]}"
                events.append(TimelineEvent(
                    event_id=e_id,
                    timestamp=p.creation_time or datetime.fromtimestamp(p_epoch, tz=timezone.utc).isoformat(),
                    category="process",
                    severity="HIGH" if is_candidate else "MEDIUM",
                    source="host_snapshot",
                    title=f"Process Spawned: {p.name} (PID: {p.pid})",
                    description=f"Process initiated by parent PID {p.ppid}. Command line: {p.cmdline or p.path}",
                    details={
                        "pid": p.pid,
                        "ppid": p.ppid,
                        "path": p.path,
                        "cmdline": p.cmdline,
                        "user": p.user
                    },
                    related_indicators=[ind for ind in [p.path, str(p.pid)] if ind]
                ))
                epoch_map[e_id] = p_epoch

    # -------------------------------------------------------------
    # 3. VOLATILE FILESYSTEM TELEMETRY
    # -------------------------------------------------------------
    if snapshot and snapshot.files:
        for f in snapshot.files:
            f_epoch = _parse_to_epoch(f.modified_time or f.created_time, anchor_epoch - 15.0)
            is_cand = candidate and (f.name == candidate.name or f.path == candidate.target_path)
            if is_cand or f.is_suspicious:
                e_id = f"evt_file_{uuid.uuid4().hex[:6]}"
                is_exec = f.extension.lower() in [".exe", ".dll", ".bat", ".ps1", ".vbs"]
                events.append(TimelineEvent(
                    event_id=e_id,
                    timestamp=f.modified_time or f.created_time or datetime.fromtimestamp(f_epoch, tz=timezone.utc).isoformat(),
                    category="filesystem",
                    severity="HIGH" if is_cand else "MEDIUM",
                    source="host_snapshot",
                    title=f"Volatile File Detected: {f.name}",
                    description=f"File present in directory: {f.path} ({f.size_bytes} bytes). Extension: {f.extension}",
                    details={"path": f.path, "size": f.size_bytes, "is_executable": is_exec},
                    related_indicators=[f.path]
                ))
                epoch_map[e_id] = f_epoch

    # -------------------------------------------------------------
    # 4. PERSISTENCE TELEMETRY
    # -------------------------------------------------------------
    if snapshot and snapshot.persistence:
        for pe in snapshot.persistence:
            pe_epoch = anchor_epoch - 60.0  # Typically set before discovery
            is_cand = candidate and (pe.name == candidate.name or pe.command == candidate.target_path or pe.file_path == candidate.target_path)
            if is_cand or pe.is_suspicious:
                e_id = f"evt_persist_{uuid.uuid4().hex[:6]}"
                events.append(TimelineEvent(
                    event_id=e_id,
                    timestamp=datetime.fromtimestamp(pe_epoch, tz=timezone.utc).isoformat(),
                    category="persistence",
                    severity="HIGH",
                    source="host_snapshot",
                    title=f"Persistence Configured: {pe.name}",
                    description=f"Startup mechanism '{pe.type}' established at '{pe.location}' pointing to '{pe.command}'.",
                    details={"location": pe.location, "command": pe.command, "type": pe.type},
                    related_indicators=[pe.command]
                ))
                epoch_map[e_id] = pe_epoch

    # -------------------------------------------------------------
    # 5. SECURITY DIFF DELTAS (WHAT CHANGED)
    # -------------------------------------------------------------
    if diff:
        diff_epoch = _parse_to_epoch(getattr(diff, "target_timestamp", None) or getattr(diff, "generated_at", None), anchor_epoch)
        changes = getattr(diff, "security_relevant_changes", []) or []
        for ch in changes:
            ch_name = getattr(ch, "name", "")
            ch_cat = getattr(ch, "category", "system")
            ch_type = getattr(ch, "change_type", "MODIFIED")
            ch_risk = getattr(ch, "risk_level", "MEDIUM")
            ch_details = getattr(ch, "details", {})
            e_id = f"evt_diff_{uuid.uuid4().hex[:6]}"
            events.append(TimelineEvent(
                event_id=e_id,
                timestamp=datetime.fromtimestamp(diff_epoch, tz=timezone.utc).isoformat(),
                category=ch_cat if ch_cat in ["process", "filesystem", "persistence", "network"] else "system",
                severity=ch_risk,
                source="security_diff",
                title=f"Host Diff ({ch_type}): {ch_name}",
                description=f"Observed state change during differential comparison. Reasons: {', '.join(getattr(ch, 'reasons', []))}",
                details=ch_details,
                related_indicators=[]
            ))
            epoch_map[e_id] = diff_epoch

    # -------------------------------------------------------------
    # 6. BEHAVIORAL SANDBOX EXECUTION & API CALL STREAM
    # -------------------------------------------------------------
    if report:
        behavioral_res = report.get("behavioral_analysis", {})
        stream = behavioral_res.get("api_call_stream", [])

        # Anchor sandbox events slightly after candidate detection
        sandbox_base_epoch = anchor_epoch + 1.0

        for idx, call in enumerate(stream):
            # API logs may have relative timestamp (e.g. 1710000001.0 or 0.5)
            raw_ts = call.get("timestamp", idx * 0.2)
            if raw_ts > 1000000000:
                call_epoch = raw_ts
            else:
                call_epoch = sandbox_base_epoch + raw_ts

            risk = call.get("risk", "LOW")
            e_id = f"evt_api_{idx}_{uuid.uuid4().hex[:4]}"
            events.append(TimelineEvent(
                event_id=e_id,
                timestamp=datetime.fromtimestamp(call_epoch, tz=timezone.utc).isoformat(),
                category="api_call",
                severity="CRITICAL" if risk == "CRITICAL" else ("HIGH" if risk == "HIGH" else "INFO"),
                source="behavioral_sandbox",
                title=f"API Call: {call.get('api', 'UnknownAPI')}",
                description=f"{call.get('process', 'Payload')} executed {call.get('api')} ({call.get('category', 'System')}). Arguments: {call.get('arguments', 'None')}",
                details=call,
                related_indicators=[]
            ))
            epoch_map[e_id] = call_epoch

        # Behavioral Filesystem Activity
        fs_raw = behavioral_res.get("filesystem_activity", [])
        if isinstance(fs_raw, list):
            for idx, fa in enumerate(fs_raw):
                f_epoch = sandbox_base_epoch + 1.5 + (idx * 0.1)
                e_id = f"evt_b_fs_{idx}_{uuid.uuid4().hex[:4]}"
                events.append(TimelineEvent(
                    event_id=e_id,
                    timestamp=datetime.fromtimestamp(f_epoch, tz=timezone.utc).isoformat(),
                    category="filesystem",
                    severity="HIGH",
                    source="behavioral_sandbox",
                    title=f"Behavioral Dropped Payload: {os.path.basename(str(fa.get('path', 'payload')))}",
                    description=f"Action: {fa.get('action')} at path: {fa.get('path')} (size: {fa.get('size', 'unknown')})",
                    details=fa if isinstance(fa, dict) else {},
                    related_indicators=[str(fa.get("path", ""))] if isinstance(fa, dict) else []
                ))
                epoch_map[e_id] = f_epoch

        # Behavioral Network Activity / C2 Beacons
        net_raw = behavioral_res.get("network_activity", [])
        if isinstance(net_raw, list):
            for idx, na in enumerate(net_raw):
                n_epoch = sandbox_base_epoch + 2.0 + (idx * 0.2)
                e_id = f"evt_b_net_{idx}_{uuid.uuid4().hex[:4]}"
                dest = str(na.get("destination", "unknown")) if isinstance(na, dict) else "unknown"
                events.append(TimelineEvent(
                    event_id=e_id,
                    timestamp=datetime.fromtimestamp(n_epoch, tz=timezone.utc).isoformat(),
                    category="network",
                    severity="HIGH",
                    source="behavioral_sandbox",
                    title=f"Outbound C2 Communication: {dest}",
                    description=f"Protocol {na.get('proto', 'TCP')} packet to {dest} ({na.get('type', 'Payload')}).",
                    details=na if isinstance(na, dict) else {},
                    related_indicators=[dest]
                ))
                epoch_map[e_id] = n_epoch

        # MITRE Mapping Events
        mitre_techs = report.get("mitre_mapping", {}).get("techniques", [])
        for idx, t in enumerate(mitre_techs):
            m_epoch = sandbox_base_epoch + 3.0 + (idx * 0.1)
            e_id = f"evt_mitre_{t.get('technique_id', idx)}"
            events.append(TimelineEvent(
                event_id=e_id,
                timestamp=datetime.fromtimestamp(m_epoch, tz=timezone.utc).isoformat(),
                category="mitre",
                severity="HIGH",
                source="mitre_mapper",
                title=f"ATT&CK Technique Identified: {t.get('technique_id')} ({t.get('name')})",
                description=f"Tactic '{t.get('tactic')}'. Evidentiary rationale: {t.get('rationale', 'Behavioral match')}",
                details=t,
                related_indicators=[]
            ))
            epoch_map[e_id] = m_epoch

    # -------------------------------------------------------------
    # 7. CHRONOLOGICAL SORTING & RELATIVE DELTAS
    # -------------------------------------------------------------
    # Sort strictly by epoch
    events.sort(key=lambda ev: epoch_map.get(ev.event_id, 0.0))

    if events:
        min_epoch = min(epoch_map.values())
        max_epoch = max(epoch_map.values())
        start_time_iso = datetime.fromtimestamp(min_epoch, tz=timezone.utc).isoformat()
        end_time_iso = datetime.fromtimestamp(max_epoch, tz=timezone.utc).isoformat()

        # Update relative_time_seconds
        for ev in events:
            ev_epoch = epoch_map.get(ev.event_id, min_epoch)
            ev.relative_time_seconds = round(ev_epoch - min_epoch, 2)
    else:
        start_time_iso = datetime.fromtimestamp(anchor_epoch, tz=timezone.utc).isoformat()
        end_time_iso = start_time_iso

    # Calculate aggregations
    cat_counts: Dict[str, int] = {}
    sev_counts: Dict[str, int] = {}
    for ev in events:
        cat_counts[ev.category] = cat_counts.get(ev.category, 0) + 1
        sev_counts[ev.severity] = sev_counts.get(ev.severity, 0) + 1

    target_id = candidate.candidate_id if candidate else (snapshot.snapshot_id if snapshot else "host_latest")
    target_type = "candidate" if candidate else ("snapshot" if snapshot else "global")

    return SecurityTimeline(
        timeline_id=f"timeline_{uuid.uuid4().hex[:8]}",
        target_id=target_id,
        target_type=target_type,
        generated_at=datetime.now(timezone.utc).isoformat(),
        start_time=start_time_iso,
        end_time=end_time_iso,
        total_events=len(events),
        event_counts_by_category=cat_counts,
        event_counts_by_severity=sev_counts,
        events=events
    )
