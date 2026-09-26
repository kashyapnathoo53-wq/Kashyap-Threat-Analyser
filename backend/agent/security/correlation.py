import os
import uuid
from typing import Dict, List, Any, Optional

from agent.models.candidate import SuspiciousCandidate
from agent.models.snapshot import SecuritySnapshot
from agent.models.correlation import (
    EvidenceNode,
    EvidenceEdge,
    AttackStoryPhase,
    AttackStoryGraph,
    AttackStory
)


def correlate_evidence(
    candidate: SuspiciousCandidate,
    report: Optional[Dict[str, Any]] = None,
    snapshot: Optional[SecuritySnapshot] = None
) -> AttackStory:
    """
    Transforms isolated candidate indicators and full analysis findings
    into an interconnected, explainable Evidence Graph and Attack Story.
    """
    story_id = f"story_{uuid.uuid4().hex[:8]}"
    nodes: Dict[str, EvidenceNode] = {}
    edges: List[EvidenceEdge] = []
    phases: List[AttackStoryPhase] = []

    # 1. Establish Root Cause Node
    root_node_id = f"node_root_{candidate.candidate_id}"
    root_sev = "CRITICAL" if candidate.priority_score >= 70 else ("HIGH" if candidate.priority_score >= 50 else "MEDIUM")
    
    label = candidate.name
    if candidate.category == "process" and candidate.metadata.get("pid"):
        label = f"{candidate.name} (PID {candidate.metadata['pid']})"

    nodes[root_node_id] = EvidenceNode(
        id=root_node_id,
        type=candidate.category,
        label=label,
        severity=root_sev,
        timestamp=candidate.discovered_at,
        details={
            "target_path": candidate.target_path,
            "cmdline": candidate.cmdline,
            "sha256": candidate.sha256,
            "priority_score": candidate.priority_score,
            "heuristics": candidate.heuristics_matched
        }
    )

    # -------------------------------------------------------------
    # PHASE 1: DISCOVERY & EXECUTION
    # -------------------------------------------------------------
    p1_nodes = [root_node_id]
    p1_narrative = (
        f"Suspicious activity was identified involving {candidate.name} via {candidate.discovery_source}. "
        f"The candidate was prioritized with a threat urgency score of {candidate.priority_score}/100. "
    )
    if candidate.heuristics_matched:
        p1_narrative += f"Heuristics initially triggered: {'; '.join(candidate.heuristics_matched)}."
    
    phases.append(AttackStoryPhase(
        phase_name="Initial Discovery & Ingestion",
        tactic="Execution",
        narrative=p1_narrative,
        node_ids=p1_nodes
    ))

    # Correlate with Snapshot Host Telemetry (Parent Process, Network Sockets)
    if snapshot:
        # Check for parent process
        if candidate.category == "process":
            cand_pid = candidate.metadata.get("pid")
            parent_proc = None
            if cand_pid:
                # Find candidate in snapshot processes
                for p in snapshot.processes:
                    if p.pid == cand_pid and p.ppid:
                        # Find parent
                        for pp in snapshot.processes:
                            if pp.pid == p.ppid:
                                parent_proc = pp
                                break
                        break

            if parent_proc:
                parent_id = f"node_proc_{parent_proc.pid}"
                nodes[parent_id] = EvidenceNode(
                    id=parent_id,
                    type="process",
                    label=f"{parent_proc.name} (PID {parent_proc.pid})",
                    severity="INFO",
                    details={"path": parent_proc.path, "cmdline": parent_proc.cmdline}
                )
                edges.append(EvidenceEdge(
                    source=parent_id,
                    target=root_node_id,
                    relation="SPAWNED",
                    label="Spawned Child Process",
                    confidence=1.0
                ))
                p1_nodes.append(parent_id)

    # -------------------------------------------------------------
    # PHASE 2: SIGNATURE EVALUATION & DETECTIONS (YARA & STATIC)
    # -------------------------------------------------------------
    p2_nodes = []
    p2_narrative_parts = []

    if report:
        static_res = report.get("static_analysis", {})
        yara_res = report.get("yara_scan", {})

        # File Node if hash exists
        sha = candidate.sha256 or static_res.get("hashes", {}).get("sha256")
        if sha:
            file_node_id = f"node_file_{sha[:12]}"
            if file_node_id not in nodes:
                nodes[file_node_id] = EvidenceNode(
                    id=file_node_id,
                    type="file",
                    label=f"Binary: {candidate.name}",
                    severity=root_sev,
                    details={
                        "sha256": sha,
                        "size_bytes": candidate.size_bytes or report.get("file_size_bytes", 0),
                        "entropy": static_res.get("entropy", {}).get("value", 0.0)
                    }
                )
                edges.append(EvidenceEdge(
                    source=root_node_id,
                    target=file_node_id,
                    relation="ASSOCIATED_BINARY",
                    label="Executable Image",
                    confidence=1.0
                ))
                p2_nodes.append(file_node_id)

        # YARA Matches
        matches = yara_res.get("matches", [])
        if matches:
            for m in matches:
                yara_id = f"node_yara_{m.get('rule', 'unknown')}"
                nodes[yara_id] = EvidenceNode(
                    id=yara_id,
                    type="yara",
                    label=f"YARA: {m.get('rule')}",
                    severity=m.get("severity", "HIGH"),
                    details={"description": m.get("description"), "strings": m.get("strings_matched", [])}
                )
                edges.append(EvidenceEdge(
                    source=root_node_id,
                    target=yara_id,
                    relation="MATCHED_SIGNATURE",
                    label="Signature Match",
                    confidence=0.95
                ))
                p2_nodes.append(yara_id)
            p2_narrative_parts.append(f"Static YARA evaluation matched {len(matches)} signature rules: {', '.join(m.get('rule') for m in matches)}.")
        else:
            p2_narrative_parts.append("No automated YARA signatures triggered on static evaluation.")

        phases.append(AttackStoryPhase(
            phase_name="Signature Evaluation & Static Characteristics",
            tactic="Defense Evasion",
            narrative=" ".join(p2_narrative_parts),
            node_ids=p2_nodes
        ))

    # -------------------------------------------------------------
    # PHASE 3: BEHAVIORAL ACTIVITY & PERSISTENCE
    # -------------------------------------------------------------
    p3_nodes = []
    p3_narrative_parts = []

    if report:
        behavioral_res = report.get("behavioral_analysis", {})
        
        # Registry persistence
        reg_raw = behavioral_res.get("registry_activity", [])
        run_keys = []
        if isinstance(reg_raw, dict):
            run_keys = reg_raw.get("run_keys", [])
        elif isinstance(reg_raw, list):
            for rk in reg_raw:
                if isinstance(rk, dict):
                    k_name = str(rk.get("key") or rk.get("path") or "")
                    if "run" in k_name.lower() or "currentversion" in k_name.lower() or rk.get("action") == "SET_VALUE":
                        run_keys.append({"key": k_name, "path": k_name, "value": rk.get("value", "")})

        if run_keys:
            for rk in run_keys:
                persist_id = f"node_persist_{uuid.uuid4().hex[:6]}"
                nodes[persist_id] = EvidenceNode(
                    id=persist_id,
                    type="persistence",
                    label=f"Registry RunKey: {rk.get('key', 'Run')}",
                    severity="HIGH",
                    details={"path": rk.get("path"), "value": rk.get("value")}
                )
                edges.append(EvidenceEdge(
                    source=root_node_id,
                    target=persist_id,
                    relation="REGISTERED_PERSISTENCE",
                    label="Configured Startup Key",
                    confidence=0.9
                ))
                p3_nodes.append(persist_id)
            p3_narrative_parts.append(f"Behavioral simulation observed the creation of {len(run_keys)} persistent startup registry key(s).")

        # Dropped files
        fs_raw = behavioral_res.get("filesystem_activity", [])
        dropped = []
        if isinstance(fs_raw, dict):
            dropped = fs_raw.get("dropped_files", [])
        elif isinstance(fs_raw, list):
            for f in fs_raw:
                if isinstance(f, dict):
                    f_path = str(f.get("path", ""))
                    dropped.append({
                        "filename": os.path.basename(f_path) if f_path else "dropped_payload",
                        "path": f_path,
                        "size_bytes": f.get("size", 0),
                        "is_executable": f_path.lower().endswith((".exe", ".dll", ".bat", ".ps1", ".vbs"))
                    })

        if dropped:
            for df in dropped[:3]:  # Top 3
                drop_id = f"node_drop_{uuid.uuid4().hex[:6]}"
                nodes[drop_id] = EvidenceNode(
                    id=drop_id,
                    type="file",
                    label=f"Dropped: {df.get('filename')}",
                    severity="HIGH" if df.get("is_executable") else "MEDIUM",
                    details={"path": df.get("path"), "size": df.get("size_bytes")}
                )
                edges.append(EvidenceEdge(
                    source=root_node_id,
                    target=drop_id,
                    relation="DROPPED",
                    label="Dropped File Payload",
                    confidence=0.9
                ))
                p3_nodes.append(drop_id)
            p3_narrative_parts.append(f"The payload attempted to drop {len(dropped)} volatile file(s) into host storage.")

        if not p3_narrative_parts:
            p3_narrative_parts.append("No active filesystem payload dropping or registry persistence was registered.")

        phases.append(AttackStoryPhase(
            phase_name="Host Modifications & Persistence",
            tactic="Persistence",
            narrative=" ".join(p3_narrative_parts),
            node_ids=p3_nodes
        ))

    # -------------------------------------------------------------
    # PHASE 4: COMMAND AND CONTROL & IOCS
    # -------------------------------------------------------------
    p4_nodes = []
    p4_narrative_parts = []

    if report:
        ioc_res = report.get("ioc_extraction", {}).get("iocs", {})
        net_res = report.get("behavioral_analysis", {}).get("network_activity", [])

        beacons = []
        if isinstance(net_res, dict):
            beacons = net_res.get("beacons", [])
        elif isinstance(net_res, list):
            for n in net_res:
                if isinstance(n, dict):
                    dest = str(n.get("destination", ""))
                    ip = n.get("domain") or (dest.split(":")[0] if ":" in dest else (dest or "remote_host"))
                    port = int(dest.split(":")[1]) if ":" in dest and dest.split(":")[1].isdigit() else 80
                    beacons.append({
                        "ip": ip,
                        "domain": n.get("domain"),
                        "port": port,
                        "proto": n.get("proto", "TCP")
                    })

        for b in beacons:
            b_ip = b.get("ip") or b.get("domain") or "remote_host"
            b_port = b.get("port", 80)
            net_id = f"node_net_{b_ip}_{b_port}"
            nodes[net_id] = EvidenceNode(
                id=net_id,
                type="network",
                label=f"C2 Beacon: {b_ip}:{b_port}",
                severity="HIGH",
                details={"proto": b.get("proto", "TCP"), "ip": b_ip, "port": b_port}
            )
            edges.append(EvidenceEdge(
                source=root_node_id,
                target=net_id,
                relation="COMMUNICATED_WITH",
                label="Outbound C2 Beacon",
                confidence=0.9
            ))
            p4_nodes.append(net_id)

        # Extracted IPs
        ips = []
        if isinstance(ioc_res, dict):
            ips = ioc_res.get("ipv4", [])
        for ip in ips[:3]:
            ip_node_id = f"node_ioc_{ip.replace('.', '_')}"
            if ip_node_id not in nodes:
                nodes[ip_node_id] = EvidenceNode(
                    id=ip_node_id,
                    type="ioc",
                    label=f"Suspicious IP: {ip}",
                    severity="HIGH",
                    details={"ip": ip}
                )
                edges.append(EvidenceEdge(
                    source=root_node_id,
                    target=ip_node_id,
                    relation="EXPOSED_INDICATOR",
                    label="Extracted Network IOC",
                    confidence=0.85
                ))
                p4_nodes.append(ip_node_id)

        if p4_nodes:
            p4_narrative_parts.append(f"Network telemetry and indicator extraction uncovered {len(p4_nodes)} distinct communication target(s).")
        else:
            p4_narrative_parts.append("No active network beacons or remote C2 channels were observed.")

        phases.append(AttackStoryPhase(
            phase_name="Command & Control and Indicator Extraction",
            tactic="Command and Control",
            narrative=" ".join(p4_narrative_parts),
            node_ids=p4_nodes
        ))

    # -------------------------------------------------------------
    # PHASE 5: MITRE ATT&CK CORRELATION
    # -------------------------------------------------------------
    if report:
        mitre_res = report.get("mitre_mapping", {}).get("techniques", [])
        for t in mitre_res[:4]:  # Top 4 techniques
            t_id = t.get("technique_id", "T0000")
            m_node_id = f"node_mitre_{t_id}"
            nodes[m_node_id] = EvidenceNode(
                id=m_node_id,
                type="mitre",
                label=f"{t_id}: {t.get('name')}",
                severity="HIGH",
                details={"tactic": t.get("tactic"), "id": t_id}
            )
            edges.append(EvidenceEdge(
                source=root_node_id,
                target=m_node_id,
                relation="EXEMPLIFIES_TECHNIQUE",
                label="ATT&CK Technique",
                confidence=0.95
            ))

    # Determine Verdict & Scores
    threat_score = 0
    verdict = "SUSPICIOUS"
    if report:
        threat_score = report.get("threat_scoring", {}).get("threat_score", candidate.priority_score)
        verdict = report.get("threat_scoring", {}).get("verdict", "SUSPICIOUS")
    else:
        threat_score = candidate.priority_score
        verdict = "CRITICAL" if threat_score >= 80 else ("SUSPICIOUS" if threat_score >= 50 else "LOW RISK")

    # Title & Narrative Construction
    if verdict in ["MALICIOUS", "CRITICAL"]:
        title = f"Confirmed Host Threat Sequence: {candidate.name}"
    elif verdict == "SUSPICIOUS":
        title = f"High-Confidence Suspicious Anomaly: {candidate.name}"
    else:
        title = f"Routine Host Activity Assessment: {candidate.name}"

    summary_narrative = (
        f"Investigation of candidate {candidate.name} ({candidate.category.upper()}) resulted in a verdict of {verdict} "
        f"with a threat score of {threat_score}/100. "
        f"The evidence graph links {len(nodes)} correlated artifacts across {len(edges)} verified relationships. "
        f"Key attack phases include: {', '.join(p.phase_name for p in phases)}."
    )

    # Compute evidentiary confidence (0-100%)
    evidence_count = len(nodes) + len(edges)
    confidence = min(98, max(50, 60 + (evidence_count * 3)))

    return AttackStory(
        story_id=story_id,
        candidate_id=candidate.candidate_id,
        report_id=report.get("report_id") if report else candidate.analysis_report_id,
        snapshot_id=candidate.snapshot_id,
        title=title,
        verdict=verdict,
        threat_score=threat_score,
        confidence_score=confidence,
        summary_narrative=summary_narrative,
        phases=phases,
        graph=AttackStoryGraph(nodes=list(nodes.values()), edges=edges),
        root_cause_node_id=root_node_id
    )
