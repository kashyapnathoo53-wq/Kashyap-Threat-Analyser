import os
import uuid
from typing import Dict, List, Any, Optional

from agent.models.candidate import SuspiciousCandidate
from agent.models.snapshot import SecuritySnapshot
from agent.models.diff import SecurityDiffResult
from agent.models.blast_radius import AffectedEntity, ContainmentAction, BlastRadiusReport


def _flatten_process_tree(node: Dict[str, Any], results: List[Dict[str, Any]]):
    """Recursively traverses emulated process tree nodes."""
    if not isinstance(node, dict):
        return
    results.append(node)
    for child in node.get("children", []):
        _flatten_process_tree(child, results)


def compute_blast_radius(
    candidate: SuspiciousCandidate,
    report: Optional[Dict[str, Any]] = None,
    snapshot: Optional[SecuritySnapshot] = None,
    diff: Optional[SecurityDiffResult] = None
) -> BlastRadiusReport:
    """
    Computes the impact footprint and blast radius across host processes,
    volatile filesystem paths, registry persistence, and network endpoints.
    """
    report_id = f"blast_{uuid.uuid4().hex[:8]}"
    affected_processes: List[AffectedEntity] = []
    affected_files: List[AffectedEntity] = []
    affected_registry: List[AffectedEntity] = []
    affected_network: List[AffectedEntity] = []
    containment_actions: List[ContainmentAction] = []

    seen_entities = set()

    # -------------------------------------------------------------
    # 1. CANDIDATE ROOT IMPACT
    # -------------------------------------------------------------
    cand_pid = candidate.metadata.get("pid")
    cand_path = candidate.target_path or candidate.metadata.get("path")
    
    if candidate.category == "process":
        proc_id = f"proc_{cand_pid or candidate.name}"
        if proc_id not in seen_entities:
            seen_entities.add(proc_id)
            affected_processes.append(AffectedEntity(
                entity_type="process",
                identifier=str(cand_pid or candidate.name),
                name=candidate.name,
                impact_type="SPAWNED",
                severity="HIGH",
                details={"cmdline": candidate.cmdline, "path": cand_path, "pid": cand_pid}
            ))
            if cand_pid:
                containment_actions.append(ContainmentAction(
                    action_id=f"act_{uuid.uuid4().hex[:6]}",
                    target_type="process",
                    target=str(cand_pid),
                    action="TERMINATE",
                    description=f"Terminate rogue process '{candidate.name}' (PID: {cand_pid})",
                    urgency="CRITICAL"
                ))

    if cand_path:
        f_id = f"file_{cand_path}"
        if f_id not in seen_entities:
            seen_entities.add(f_id)
            affected_files.append(AffectedEntity(
                entity_type="file",
                identifier=cand_path,
                name=os.path.basename(cand_path),
                impact_type="DROPPED" if "temp" in cand_path.lower() else "MODIFIED",
                severity="HIGH",
                details={"path": cand_path, "sha256": candidate.sha256}
            ))
            containment_actions.append(ContainmentAction(
                action_id=f"act_{uuid.uuid4().hex[:6]}",
                target_type="file",
                target=cand_path,
                action="QUARANTINE",
                description=f"Isolate file payload to secure quarantine vault: {cand_path}",
                urgency="HIGH"
            ))

    # -------------------------------------------------------------
    # 2. BEHAVIORAL SANDBOX TRACING
    # -------------------------------------------------------------
    if report:
        behavioral_res = report.get("behavioral_analysis", {})

        # Process Tree
        ptree = behavioral_res.get("process_tree")
        if isinstance(ptree, dict):
            tree_nodes = []
            _flatten_process_tree(ptree, tree_nodes)
            for pnode in tree_nodes:
                p_name = pnode.get("name", "unknown")
                p_pid = pnode.get("pid")
                proc_key = f"proc_b_{p_pid or p_name}"
                if proc_key not in seen_entities and p_name != candidate.name:
                    seen_entities.add(proc_key)
                    affected_processes.append(AffectedEntity(
                        entity_type="process",
                        identifier=str(p_pid or p_name),
                        name=p_name,
                        impact_type="SPAWNED",
                        severity="MEDIUM",
                        details=pnode
                    ))
                    if p_pid:
                        containment_actions.append(ContainmentAction(
                            action_id=f"act_{uuid.uuid4().hex[:6]}",
                            target_type="process",
                            target=str(p_pid),
                            action="TERMINATE",
                            description=f"Terminate child/spawned process '{p_name}' (PID: {p_pid})",
                            urgency="HIGH"
                        ))

        # API Call Stream (Injections)
        stream = behavioral_res.get("api_call_stream", [])
        for call in stream:
            api_name = call.get("api", "")
            if api_name in ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtQueueApcThread"]:
                inj_target = call.get("process", "TargetProcess")
                inj_key = f"inj_{inj_target}"
                if inj_key not in seen_entities:
                    seen_entities.add(inj_key)
                    affected_processes.append(AffectedEntity(
                        entity_type="process",
                        identifier=inj_target,
                        name=f"Injected: {inj_target}",
                        impact_type="INJECTED",
                        severity="CRITICAL",
                        details=call
                    ))

        # Filesystem Drops
        fs_activity = behavioral_res.get("filesystem_activity", [])
        if isinstance(fs_activity, list):
            for fa in fs_activity:
                if isinstance(fa, dict):
                    fpath = str(fa.get("path", ""))
                    if fpath and fpath not in seen_entities:
                        seen_entities.add(fpath)
                        affected_files.append(AffectedEntity(
                            entity_type="file",
                            identifier=fpath,
                            name=os.path.basename(fpath),
                            impact_type="DROPPED" if "CREATE" in str(fa.get("action")) else "MODIFIED",
                            severity="HIGH",
                            details=fa
                        ))
                        containment_actions.append(ContainmentAction(
                            action_id=f"act_{uuid.uuid4().hex[:6]}",
                            target_type="file",
                            target=fpath,
                            action="QUARANTINE",
                            description=f"Quarantine dropped secondary payload: {fpath}",
                            urgency="HIGH"
                        ))

        # Registry Persistence
        reg_activity = behavioral_res.get("registry_activity", [])
        if isinstance(reg_activity, list):
            for ra in reg_activity:
                if isinstance(ra, dict):
                    rkey = str(ra.get("key") or ra.get("path") or "")
                    if rkey and rkey not in seen_entities:
                        seen_entities.add(rkey)
                        affected_registry.append(AffectedEntity(
                            entity_type="registry",
                            identifier=rkey,
                            name=os.path.basename(rkey) or rkey,
                            impact_type="PERSISTED",
                            severity="CRITICAL" if "run" in rkey.lower() else "HIGH",
                            details=ra
                        ))
                        containment_actions.append(ContainmentAction(
                            action_id=f"act_{uuid.uuid4().hex[:6]}",
                            target_type="registry",
                            target=rkey,
                            action="DELETE_KEY",
                            description=f"Delete malicious startup registry key: {rkey}",
                            urgency="CRITICAL"
                        ))

        # Network Activity
        net_activity = behavioral_res.get("network_activity", [])
        if isinstance(net_activity, list):
            for na in net_activity:
                if isinstance(na, dict):
                    dest = str(na.get("destination") or na.get("domain") or "")
                    if dest and dest not in seen_entities:
                        seen_entities.add(dest)
                        ip_clean = dest.split(":")[0]
                        affected_network.append(AffectedEntity(
                            entity_type="network",
                            identifier=dest,
                            name=dest,
                            impact_type="BEACONED",
                            severity="HIGH",
                            details=na
                        ))
                        containment_actions.append(ContainmentAction(
                            action_id=f"act_{uuid.uuid4().hex[:6]}",
                            target_type="network",
                            target=ip_clean,
                            action="BLOCK_FIREWALL",
                            description=f"Block outbound egress communication to C2 destination: {dest}",
                            urgency="HIGH"
                        ))

    # -------------------------------------------------------------
    # 3. LIVE SNAPSHOT CORRELATION
    # -------------------------------------------------------------
    if snapshot and cand_pid:
        # Correlate active sockets belonging to this PID
        for net_conn in snapshot.network:
            if net_conn.pid == cand_pid:
                endpoint = f"{net_conn.remote_addr}:{net_conn.remote_port}" if net_conn.remote_addr else net_conn.local_addr
                if endpoint not in seen_entities:
                    seen_entities.add(endpoint)
                    affected_network.append(AffectedEntity(
                        entity_type="network",
                        identifier=endpoint,
                        name=f"Live Socket ({net_conn.proto})",
                        impact_type="BEACONED",
                        severity="HIGH" if net_conn.remote_addr else "LOW",
                        details={"local": net_conn.local_addr, "remote": net_conn.remote_addr, "state": net_conn.state}
                    ))

    # -------------------------------------------------------------
    # 4. BLAST METRIC & SCOPE CALCULATION
    # -------------------------------------------------------------
    total_entities = len(affected_processes) + len(affected_files) + len(affected_registry) + len(affected_network)

    raw_score = (
        len(affected_processes) * 15 +
        len(affected_registry) * 25 +
        len(affected_network) * 20 +
        len(affected_files) * 10
    )

    if report:
        threat_score = report.get("threat_scoring", {}).get("threat_score", 50)
        # Blend threat score with entity footprint
        blast_score = min(100, max(15, int((raw_score * 0.6) + (threat_score * 0.4))))
    else:
        blast_score = min(100, max(10, raw_score))

    # Classify Scope Level
    if blast_score >= 75 or len(affected_registry) > 0 and len(affected_network) > 0:
        scope_level = "HOST_WIDE_COMPROMISE"
    elif blast_score >= 45 or len(affected_registry) > 0:
        scope_level = "PERSISTED"
    elif blast_score >= 20 or total_entities > 1:
        scope_level = "LOCAL_SURFACE"
    else:
        scope_level = "CONTAINED"

    summary_narrative = (
        f"Blast radius analysis for '{candidate.name}' scored {blast_score}/100 with scope classification '{scope_level}'. "
        f"Identified {total_entities} affected host entity/entities: {len(affected_processes)} process(es), "
        f"{len(affected_files)} file(s), {len(affected_registry)} registry hook(s), and {len(affected_network)} network endpoint(s). "
        f"Generated {len(containment_actions)} prioritized containment recommendation(s)."
    )

    return BlastRadiusReport(
        report_id=report_id,
        candidate_id=candidate.candidate_id,
        candidate_name=candidate.name,
        scope_level=scope_level,
        blast_score=blast_score,
        total_affected_entities=total_entities,
        affected_processes=affected_processes,
        affected_files=affected_files,
        affected_registry=affected_registry,
        affected_network=affected_network,
        summary_narrative=summary_narrative,
        containment_actions=containment_actions
    )
