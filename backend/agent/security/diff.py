import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple

from agent.models.snapshot import SecuritySnapshot
from agent.models.diff import DiffItem, CategoryDiff, SecurityDiffResult
from agent.security.suspicious_items import SUSPICIOUS_PORTS, SUSPICIOUS_SCRIPT_EXTENSIONS


def _parse_iso_ts(ts_str: Optional[str]) -> Optional[datetime]:
    if not ts_str:
        return None
    try:
        # Normalize trailing Z if present
        cleaned = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except Exception:
        return None


def compute_security_diff(
    target_snapshot: SecuritySnapshot,
    base_snapshot: Optional[SecuritySnapshot] = None
) -> SecurityDiffResult:
    """
    Compares target_snapshot against base_snapshot across all security attack surfaces:
    Processes, Persistence, Services, Scheduled Tasks, Network, Files, and Browser.
    
    If base_snapshot is None, target_snapshot is evaluated as an initial baseline.
    """
    diff_id = f"diff_{uuid.uuid4().hex[:8]}"
    now_iso = datetime.now(timezone.utc).isoformat()
    
    target_ts_dt = _parse_iso_ts(target_snapshot.timestamp)
    base_ts_dt = _parse_iso_ts(base_snapshot.timestamp) if base_snapshot else None
    
    time_delta: Optional[float] = None
    if base_ts_dt and target_ts_dt:
        time_delta = round((target_ts_dt - base_ts_dt).total_seconds(), 2)

    categories: Dict[str, CategoryDiff] = {}
    all_security_relevant: List[DiffItem] = []

    # 1. Diff Processes
    proc_diff = _diff_processes(base_snapshot, target_snapshot)
    categories["processes"] = proc_diff
    all_security_relevant.extend([i for i in proc_diff.items if i.is_security_relevant])

    # 2. Diff Persistence Mechanisms
    persist_diff = _diff_persistence(base_snapshot, target_snapshot)
    categories["persistence"] = persist_diff
    all_security_relevant.extend([i for i in persist_diff.items if i.is_security_relevant])

    # 3. Diff Services
    services_diff = _diff_services(base_snapshot, target_snapshot)
    categories["services"] = services_diff
    all_security_relevant.extend([i for i in services_diff.items if i.is_security_relevant])

    # 4. Diff Scheduled Tasks
    tasks_diff = _diff_scheduled_tasks(base_snapshot, target_snapshot)
    categories["scheduled_tasks"] = tasks_diff
    all_security_relevant.extend([i for i in tasks_diff.items if i.is_security_relevant])

    # 5. Diff Network Connections
    net_diff = _diff_network(base_snapshot, target_snapshot)
    categories["network"] = net_diff
    all_security_relevant.extend([i for i in net_diff.items if i.is_security_relevant])

    # 6. Diff Files
    files_diff = _diff_files(base_snapshot, target_snapshot)
    categories["files"] = files_diff
    all_security_relevant.extend([i for i in files_diff.items if i.is_security_relevant])

    # 7. Diff Browser Footprint
    browser_diff = _diff_browser(base_snapshot, target_snapshot)
    categories["browser"] = browser_diff
    all_security_relevant.extend([i for i in browser_diff.items if i.is_security_relevant])

    # Aggregate Metrics
    total_added = sum(c.added_count for c in categories.values())
    total_removed = sum(c.removed_count for c in categories.values())
    total_modified = sum(c.modified_count for c in categories.values())
    
    crit_count = sum(1 for i in all_security_relevant if i.risk_level == "CRITICAL")
    high_count = sum(1 for i in all_security_relevant if i.risk_level == "HIGH")
    med_count = sum(1 for i in all_security_relevant if i.risk_level == "MEDIUM")

    if crit_count > 0:
        verdict = "CRITICAL THREATS OBSERVED"
        verdict_color = "#ef4444"
    elif high_count > 0:
        verdict = "SUSPICIOUS ACTIVITY DETECTED"
        verdict_color = "#f97316"
    elif med_count > 0:
        verdict = "HOST DRIFT / POLICY WARNING"
        verdict_color = "#eab308"
    elif total_added + total_removed + total_modified > 0:
        verdict = "BENIGN SYSTEM CHANGES"
        verdict_color = "#3b82f6"
    else:
        verdict = "NO STATE CHANGES DETECTED"
        verdict_color = "#22c55e"

    summary = {
        "total_added": total_added,
        "total_removed": total_removed,
        "total_modified": total_modified,
        "total_security_relevant": len(all_security_relevant),
        "critical_changes": crit_count,
        "high_risk_changes": high_count,
        "medium_risk_changes": med_count,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "is_baseline_only": base_snapshot is None
    }

    return SecurityDiffResult(
        diff_id=diff_id,
        base_snapshot_id=base_snapshot.snapshot_id if base_snapshot else None,
        target_snapshot_id=target_snapshot.snapshot_id,
        generated_at=now_iso,
        base_timestamp=base_snapshot.timestamp if base_snapshot else None,
        target_timestamp=target_snapshot.timestamp,
        time_delta_seconds=time_delta,
        summary=summary,
        categories=categories,
        security_relevant_changes=all_security_relevant
    )


# =====================================================================
# INDIVIDUAL CATEGORY DIFF ALGORITHMS
# =====================================================================

def _diff_processes(base: Optional[SecuritySnapshot], target: SecuritySnapshot) -> CategoryDiff:
    diff = CategoryDiff(category="processes")
    base_map = {}
    if base:
        for p in base.processes:
            # Identity key: (name, path) or (pid, name)
            key = f"{p.name.lower()}|{(p.path or '').lower()}"
            base_map[key] = p

    target_map = {}
    for p in target.processes:
        key = f"{p.name.lower()}|{(p.path or '').lower()}"
        target_map[key] = p

    if not base:
        # Initial baseline: flag pre-screened suspicious processes as security relevant
        for key, p in target_map.items():
            if p.is_suspicious:
                diff.items.append(DiffItem(
                    change_type="ADDED",
                    category="process",
                    identifier=f"PID {p.pid} - {p.name}",
                    name=p.name,
                    details={"pid": p.pid, "path": p.path, "cmdline": p.cmdline},
                    target_value=p.model_dump(),
                    is_security_relevant=True,
                    risk_level="CRITICAL" if any("ransomware" in r.lower() or "mimikatz" in r.lower() for r in p.suspicious_reasons) else "HIGH",
                    reasons=p.suspicious_reasons or ["Baseline suspicious process"]
                ))
                diff.security_relevant_count += 1
        diff.added_count = len(target_map)
        return diff

    # 1. Added Processes
    for key, p in target_map.items():
        if key not in base_map:
            diff.added_count += 1
            is_sus = p.is_suspicious
            reasons = list(p.suspicious_reasons)

            risk = "INFO"
            if is_sus:
                risk = "CRITICAL" if any("ransomware" in r.lower() or "mimikatz" in r.lower() for r in reasons) else "HIGH"
            elif p.path and ("temp" in p.path.lower() or "appdata" in p.path.lower()):
                is_sus = True
                risk = "HIGH"
                reasons.append("New process running out of user-writable AppData/Temp directory")
            else:
                reasons.append("New process launched since prior baseline")

            item = DiffItem(
                change_type="ADDED",
                category="process",
                identifier=f"PID {p.pid} - {p.name}",
                name=p.name,
                details={"pid": p.pid, "path": p.path, "cmdline": p.cmdline},
                target_value=p.model_dump(),
                is_security_relevant=is_sus,
                risk_level=risk,
                reasons=reasons
            )
            diff.items.append(item)
            if is_sus:
                diff.security_relevant_count += 1

    # 2. Removed Processes
    for key, p in base_map.items():
        if key not in target_map:
            diff.removed_count += 1
            is_sus = p.is_suspicious
            reasons = ["Process terminated since prior baseline"]
            if is_sus:
                reasons.append("Previously suspicious process terminated/unloaded")
            diff.items.append(DiffItem(
                change_type="REMOVED",
                category="process",
                identifier=f"PID {p.pid} - {p.name}",
                name=p.name,
                details={"pid": p.pid, "path": p.path},
                base_value=p.model_dump(),
                is_security_relevant=is_sus,
                risk_level="MEDIUM" if is_sus else "INFO",
                reasons=reasons
            ))
            if is_sus:
                diff.security_relevant_count += 1

    return diff


def _diff_persistence(base: Optional[SecuritySnapshot], target: SecuritySnapshot) -> CategoryDiff:
    diff = CategoryDiff(category="persistence")
    base_map = {}
    if base:
        for p in base.persistence:
            key = f"{p.location.lower()}|{p.name.lower()}"
            base_map[key] = p

    target_map = {}
    for p in target.persistence:
        key = f"{p.location.lower()}|{p.name.lower()}"
        target_map[key] = p

    if not base:
        for key, p in target_map.items():
            if p.is_suspicious:
                diff.items.append(DiffItem(
                    change_type="ADDED",
                    category="persistence",
                    identifier=f"{p.location}\\{p.name}",
                    name=p.name,
                    details={"command": p.command, "location": p.location, "type": p.type},
                    target_value=p.model_dump(),
                    is_security_relevant=True,
                    risk_level="CRITICAL",
                    reasons=p.suspicious_reasons
                ))
                diff.security_relevant_count += 1
        diff.added_count = len(target_map)
        return diff

    # Added Persistence
    for key, p in target_map.items():
        if key not in base_map:
            diff.added_count += 1
            reasons = ["New startup persistence mechanism registered"]
            if p.is_suspicious:
                reasons.extend(p.suspicious_reasons)
                risk = "CRITICAL"
            else:
                risk = "HIGH"

            diff.items.append(DiffItem(
                change_type="ADDED",
                category="persistence",
                identifier=f"{p.location}\\{p.name}",
                name=p.name,
                details={"command": p.command, "location": p.location, "type": p.type},
                target_value=p.model_dump(),
                is_security_relevant=True,
                risk_level=risk,
                reasons=reasons
            ))
            diff.security_relevant_count += 1
        else:
            # Check for modification
            base_p = base_map[key]
            if base_p.command != p.command:
                diff.modified_count += 1
                diff.items.append(DiffItem(
                    change_type="MODIFIED",
                    category="persistence",
                    identifier=f"{p.location}\\{p.name}",
                    name=p.name,
                    details={"old_command": base_p.command, "new_command": p.command},
                    base_value=base_p.model_dump(),
                    target_value=p.model_dump(),
                    is_security_relevant=True,
                    risk_level="CRITICAL",
                    reasons=["Persistence command target modified"]
                ))
                diff.security_relevant_count += 1

    # Removed Persistence
    for key, p in base_map.items():
        if key not in target_map:
            diff.removed_count += 1
            diff.items.append(DiffItem(
                change_type="REMOVED",
                category="persistence",
                identifier=f"{p.location}\\{p.name}",
                name=p.name,
                details={"command": p.command, "location": p.location},
                base_value=p.model_dump(),
                is_security_relevant=False,
                risk_level="INFO",
                reasons=["Startup persistence mechanism removed"]
            ))

    return diff


def _diff_services(base: Optional[SecuritySnapshot], target: SecuritySnapshot) -> CategoryDiff:
    diff = CategoryDiff(category="services")
    base_map = {s.name.lower(): s for s in base.services} if base else {}
    target_map = {s.name.lower(): s for s in target.services}

    if not base:
        for key, s in target_map.items():
            if s.is_suspicious:
                diff.items.append(DiffItem(
                    change_type="ADDED",
                    category="service",
                    identifier=f"Service: {s.name}",
                    name=s.name,
                    details={"binary_path": s.binary_path, "start_mode": s.start_mode},
                    target_value=s.model_dump(),
                    is_security_relevant=True,
                    risk_level="HIGH",
                    reasons=s.suspicious_reasons
                ))
                diff.security_relevant_count += 1
        diff.added_count = len(target_map)
        return diff

    # Added Services
    for key, s in target_map.items():
        if key not in base_map:
            diff.added_count += 1
            is_sus = s.is_suspicious
            reasons = ["New Windows service installed"]
            if is_sus:
                reasons.extend(s.suspicious_reasons)
                risk = "CRITICAL"
            else:
                risk = "HIGH"

            diff.items.append(DiffItem(
                change_type="ADDED",
                category="service",
                identifier=f"Service: {s.name}",
                name=s.name,
                details={"binary_path": s.binary_path, "start_mode": s.start_mode},
                target_value=s.model_dump(),
                is_security_relevant=True,
                risk_level=risk,
                reasons=reasons
            ))
            diff.security_relevant_count += 1
        else:
            base_s = base_map[key]
            if (base_s.binary_path != s.binary_path) or (base_s.start_mode != s.start_mode):
                diff.modified_count += 1
                reasons = []
                is_sus = False
                if base_s.binary_path != s.binary_path:
                    reasons.append(f"Service binary path modified: {s.binary_path}")
                    is_sus = True
                if base_s.start_mode != s.start_mode:
                    reasons.append(f"Service startup mode changed: {base_s.start_mode} -> {s.start_mode}")

                diff.items.append(DiffItem(
                    change_type="MODIFIED",
                    category="service",
                    identifier=f"Service: {s.name}",
                    name=s.name,
                    details={"old_binary": base_s.binary_path, "new_binary": s.binary_path},
                    base_value=base_s.model_dump(),
                    target_value=s.model_dump(),
                    is_security_relevant=is_sus,
                    risk_level="CRITICAL" if is_sus else "MEDIUM",
                    reasons=reasons
                ))
                if is_sus:
                    diff.security_relevant_count += 1

    # Removed Services
    for key, s in base_map.items():
        if key not in target_map:
            diff.removed_count += 1
            diff.items.append(DiffItem(
                change_type="REMOVED",
                category="service",
                identifier=f"Service: {s.name}",
                name=s.name,
                details={"binary_path": s.binary_path},
                base_value=s.model_dump(),
                is_security_relevant=False,
                risk_level="INFO",
                reasons=["Service uninstalled / removed"]
            ))

    return diff


def _diff_scheduled_tasks(base: Optional[SecuritySnapshot], target: SecuritySnapshot) -> CategoryDiff:
    diff = CategoryDiff(category="scheduled_tasks")
    base_map = {f"{t.path.lower()}|{t.name.lower()}": t for t in base.scheduled_tasks} if base else {}
    target_map = {f"{t.path.lower()}|{t.name.lower()}": t for t in target.scheduled_tasks}

    if not base:
        for key, t in target_map.items():
            if t.is_suspicious:
                diff.items.append(DiffItem(
                    change_type="ADDED",
                    category="scheduled_task",
                    identifier=f"Task: {t.name}",
                    name=t.name,
                    details={"action": t.action, "path": t.path},
                    target_value=t.model_dump(),
                    is_security_relevant=True,
                    risk_level="HIGH",
                    reasons=t.suspicious_reasons
                ))
                diff.security_relevant_count += 1
        diff.added_count = len(target_map)
        return diff

    for key, t in target_map.items():
        if key not in base_map:
            diff.added_count += 1
            reasons = ["New scheduled task created"]
            if t.is_suspicious:
                reasons.extend(t.suspicious_reasons)
                risk = "CRITICAL"
            else:
                risk = "HIGH"

            diff.items.append(DiffItem(
                change_type="ADDED",
                category="scheduled_task",
                identifier=f"Task: {t.name}",
                name=t.name,
                details={"action": t.action, "path": t.path},
                target_value=t.model_dump(),
                is_security_relevant=True,
                risk_level=risk,
                reasons=reasons
            ))
            diff.security_relevant_count += 1
        else:
            base_t = base_map[key]
            if base_t.action != t.action:
                diff.modified_count += 1
                diff.items.append(DiffItem(
                    change_type="MODIFIED",
                    category="scheduled_task",
                    identifier=f"Task: {t.name}",
                    name=t.name,
                    details={"old_action": base_t.action, "new_action": t.action},
                    base_value=base_t.model_dump(),
                    target_value=t.model_dump(),
                    is_security_relevant=True,
                    risk_level="CRITICAL",
                    reasons=["Scheduled task action / command modified"]
                ))
                diff.security_relevant_count += 1

    for key, t in base_map.items():
        if key not in target_map:
            diff.removed_count += 1
            diff.items.append(DiffItem(
                change_type="REMOVED",
                category="scheduled_task",
                identifier=f"Task: {t.name}",
                name=t.name,
                details={"action": t.action},
                base_value=t.model_dump(),
                is_security_relevant=False,
                risk_level="INFO",
                reasons=["Scheduled task deleted"]
            ))

    return diff


def _diff_network(base: Optional[SecuritySnapshot], target: SecuritySnapshot) -> CategoryDiff:
    diff = CategoryDiff(category="network")
    base_map = {}
    if base:
        for n in base.network:
            key = f"{n.proto.upper()}|{n.local_addr}:{n.local_port}|{n.remote_addr or '*'}:{n.remote_port or 0}"
            base_map[key] = n

    target_map = {}
    for n in target.network:
        key = f"{n.proto.upper()}|{n.local_addr}:{n.local_port}|{n.remote_addr or '*'}:{n.remote_port or 0}"
        target_map[key] = n

    if not base:
        for key, n in target_map.items():
            if n.is_suspicious:
                diff.items.append(DiffItem(
                    change_type="ADDED",
                    category="network",
                    identifier=f"{n.proto} {n.local_addr}:{n.local_port} -> {n.remote_addr}:{n.remote_port}",
                    name=n.process_name or f"PID {n.pid}",
                    details={"pid": n.pid, "state": n.state},
                    target_value=n.model_dump(),
                    is_security_relevant=True,
                    risk_level="HIGH",
                    reasons=n.suspicious_reasons
                ))
                diff.security_relevant_count += 1
        diff.added_count = len(target_map)
        return diff

    for key, n in target_map.items():
        if key not in base_map:
            diff.added_count += 1
            is_sus = n.is_suspicious
            reasons = list(n.suspicious_reasons)
            risk = "INFO"

            if is_sus:
                risk = "CRITICAL"
            elif n.remote_port in SUSPICIOUS_PORTS:
                is_sus = True
                risk = "CRITICAL"
                reasons.append(f"Connection opened to suspicious C2 port ({n.remote_port})")
            elif n.process_name and any(p in n.process_name.lower() for p in ["powershell", "cmd.exe", "wscript", "cscript"]):
                is_sus = True
                risk = "HIGH"
                reasons.append(f"Command shell process ({n.process_name}) established network connection")
            elif n.state == "LISTENING":
                risk = "LOW"
                reasons.append("New local port opened for listening")
            else:
                reasons.append("New network socket established")

            diff.items.append(DiffItem(
                change_type="ADDED",
                category="network",
                identifier=f"{n.proto} {n.local_addr}:{n.local_port} -> {n.remote_addr}:{n.remote_port}",
                name=n.process_name or f"PID {n.pid}",
                details={"pid": n.pid, "state": n.state},
                target_value=n.model_dump(),
                is_security_relevant=is_sus,
                risk_level=risk,
                reasons=reasons
            ))
            if is_sus:
                diff.security_relevant_count += 1

    for key, n in base_map.items():
        if key not in target_map:
            diff.removed_count += 1
            diff.items.append(DiffItem(
                change_type="REMOVED",
                category="network",
                identifier=f"{n.proto} {n.local_addr}:{n.local_port} -> {n.remote_addr}:{n.remote_port}",
                name=n.process_name or f"PID {n.pid}",
                details={"pid": n.pid},
                base_value=n.model_dump(),
                is_security_relevant=False,
                risk_level="INFO",
                reasons=["Connection terminated / closed"]
            ))

    return diff


def _diff_files(base: Optional[SecuritySnapshot], target: SecuritySnapshot) -> CategoryDiff:
    diff = CategoryDiff(category="files")
    base_map = {f.path.lower(): f for f in base.files} if base else {}
    target_map = {f.path.lower(): f for f in target.files}

    if not base:
        for key, f in target_map.items():
            if f.is_suspicious:
                diff.items.append(DiffItem(
                    change_type="ADDED",
                    category="file",
                    identifier=f.path,
                    name=f.name,
                    details={"category": f.category, "sha256": f.sha256},
                    target_value=f.model_dump(),
                    is_security_relevant=True,
                    risk_level="HIGH",
                    reasons=f.suspicious_reasons
                ))
                diff.security_relevant_count += 1
        diff.added_count = len(target_map)
        return diff

    for key, f in target_map.items():
        if key not in base_map:
            diff.added_count += 1
            is_sus = f.is_suspicious
            reasons = list(f.suspicious_reasons)
            risk = "INFO"

            if is_sus:
                risk = "CRITICAL" if any("double" in r.lower() for r in reasons) else "HIGH"
            elif f.extension.lower() in [".exe", ".dll", ".vbs", ".ps1", ".bat", ".scr", ".hta"]:
                is_sus = True
                risk = "HIGH"
                reasons.append(f"New executable dropped in monitored path ({f.extension})")
            else:
                reasons.append("New file detected in volatile directory")

            diff.items.append(DiffItem(
                change_type="ADDED",
                category="file",
                identifier=f.path,
                name=f.name,
                details={"category": f.category, "sha256": f.sha256},
                target_value=f.model_dump(),
                is_security_relevant=is_sus,
                risk_level=risk,
                reasons=reasons
            ))
            if is_sus:
                diff.security_relevant_count += 1
        else:
            base_f = base_map[key]
            if (base_f.sha256 and f.sha256 and base_f.sha256 != f.sha256) or (base_f.size_bytes != f.size_bytes):
                diff.modified_count += 1
                is_exe = f.extension.lower() in [".exe", ".dll", ".sys"]
                diff.items.append(DiffItem(
                    change_type="MODIFIED",
                    category="file",
                    identifier=f.path,
                    name=f.name,
                    details={"old_sha256": base_f.sha256, "new_sha256": f.sha256},
                    base_value=base_f.model_dump(),
                    target_value=f.model_dump(),
                    is_security_relevant=is_exe,
                    risk_level="HIGH" if is_exe else "LOW",
                    reasons=["File content modified (hash/size changed)"]
                ))
                if is_exe:
                    diff.security_relevant_count += 1

    for key, f in base_map.items():
        if key not in target_map:
            diff.removed_count += 1
            diff.items.append(DiffItem(
                change_type="REMOVED",
                category="file",
                identifier=f.path,
                name=f.name,
                details={"category": f.category},
                base_value=f.model_dump(),
                is_security_relevant=False,
                risk_level="INFO",
                reasons=["Volatile file deleted / cleaned up"]
            ))

    return diff


def _diff_browser(base: Optional[SecuritySnapshot], target: SecuritySnapshot) -> CategoryDiff:
    diff = CategoryDiff(category="browser")
    base_map = {b.name.lower(): b for b in base.browser} if base else {}
    target_map = {b.name.lower(): b for b in target.browser}

    for key, b in target_map.items():
        if key not in base_map:
            diff.added_count += 1
            diff.items.append(DiffItem(
                change_type="ADDED",
                category="browser",
                identifier=b.name,
                name=b.name,
                details={"profiles": len(b.profile_paths)},
                target_value=b.model_dump(),
                is_security_relevant=False,
                risk_level="INFO",
                reasons=["New browser detected"]
            ))
        else:
            base_b = base_map[key]
            if len(b.suspicious_extensions) > len(base_b.suspicious_extensions):
                diff.modified_count += 1
                diff.items.append(DiffItem(
                    change_type="MODIFIED",
                    category="browser",
                    identifier=b.name,
                    name=b.name,
                    details={"suspicious_extensions": b.suspicious_extensions},
                    base_value=base_b.model_dump(),
                    target_value=b.model_dump(),
                    is_security_relevant=True,
                    risk_level="CRITICAL",
                    reasons=["New suspicious browser extension detected"]
                ))
                diff.security_relevant_count += 1

    return diff
