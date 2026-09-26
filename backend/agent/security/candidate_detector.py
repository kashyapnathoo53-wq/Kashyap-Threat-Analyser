import os
import re
import uuid
import hashlib
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any

from agent.models.snapshot import SecuritySnapshot, ProcessItem, PersistenceItem, ServiceItem, ScheduledTaskItem, NetworkConnectionItem, FileItem
from agent.models.diff import SecurityDiffResult, DiffItem
from agent.models.candidate import SuspiciousCandidate, CandidateStatus


def _calculate_file_sha256(filepath: str) -> Optional[str]:
    """Calculates SHA-256 of a local file safely if accessible."""
    try:
        clean_path = filepath.strip("\"' ")
        p = Path(clean_path)
        if p.is_file() and p.exists():
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
    except Exception:
        pass
    return None


def _get_file_size(filepath: str) -> Optional[int]:
    try:
        clean_path = filepath.strip("\"' ")
        p = Path(clean_path)
        if p.is_file() and p.exists():
            return p.stat().st_size
    except Exception:
        pass
    return None


def _extract_executable_path(raw_command: str) -> Optional[str]:
    """Extracts binary path from command strings that may contain flags and arguments."""
    if not raw_command:
        return None
    raw = raw_command.strip()
    # Quoted path e.g. "C:\Path with spaces\app.exe" -arg
    if raw.startswith('"'):
        end_q = raw.find('"', 1)
        if end_q != -1:
            return raw[1:end_q]
    # Unquoted path ending with .exe / .vbs / .bat
    match = re.search(r"^[A-Za-z]:\\[^\s]+\.(?:exe|dll|vbs|bat|cmd|ps1|scr|hta)", raw, re.IGNORECASE)
    if match:
        return match.group(0)
    # First token fallback
    tokens = raw.split()
    if tokens:
        return tokens[0].strip("\"'")
    return None


def calculate_candidate_priority(
    category: str,
    reasons: List[str],
    path: Optional[str] = None,
    cmdline: Optional[str] = None,
    is_diff: bool = False
) -> int:
    """
    Computes an explainable priority score (0–100) based on observable threat signals.
    """
    score = 25  # Base detection score

    text_to_eval = " ".join(reasons).lower() + " " + (path or "").lower() + " " + (cmdline or "").lower()

    # 1. Critical Indicators (+35 - +45)
    if any(k in text_to_eval for k in ["ransomware", "vssadmin", "shadows", "recoveryenabled"]):
        score += 45
    if any(k in text_to_eval for k in ["mimikatz", "lazagne", "credential dumping"]):
        score += 40
    if any(k in text_to_eval for k in ["encoded powershell", "-enc", "-encodedcommand"]):
        score += 35
    if "double extension" in text_to_eval:
        score += 35
    if any(k in text_to_eval for k in ["c2 port", "suspicious port", "port (4444)"]):
        score += 30

    # 2. Execution Location / File Path (+15 - +25)
    if "temp" in text_to_eval or "appdata\\local\\temp" in text_to_eval:
        score += 25
    elif "appdata" in text_to_eval:
        score += 15

    # 3. Persistence & Service Hijacking (+20 - +30)
    if category == "persistence":
        score += 20
        if any(ext in text_to_eval for ext in [".vbs", ".ps1", ".bat", ".hta"]):
            score += 15
    elif category == "service":
        if "binary path modified" in text_to_eval or "user-writable" in text_to_eval:
            score += 30
        else:
            score += 15

    # 4. Command Shell Spawning Network (+25)
    if category == "network" and any(sh in text_to_eval for sh in ["powershell", "cmd.exe", "wscript"]):
        score += 25

    # 5. Delta Modifier: State changes detected in diff are more urgent (+10)
    if is_diff:
        score += 10

    # Bounded between 15 and 100
    return max(15, min(100, score))


def detect_candidates_from_snapshot(snapshot: SecuritySnapshot) -> List[SuspiciousCandidate]:
    """
    Scans a SecuritySnapshot and extracts high-priority suspicious candidates ready for queueing.
    """
    candidates: List[SuspiciousCandidate] = []
    seen_keys = set()

    # 1. Suspicious Processes
    for p in snapshot.processes:
        if p.is_suspicious:
            target_path = p.path or _extract_executable_path(p.cmdline or "")
            sha256 = _calculate_file_sha256(target_path) if target_path else None
            size_bytes = _get_file_size(target_path) if target_path else None

            dedup_key = f"process|{p.name.lower()}|{target_path or ''}|{p.cmdline or ''}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            score = calculate_candidate_priority(
                category="process",
                reasons=p.suspicious_reasons,
                path=target_path,
                cmdline=p.cmdline,
                is_diff=False
            )

            cand_id = f"cand_proc_{p.pid}_{uuid.uuid4().hex[:6]}"
            candidates.append(SuspiciousCandidate(
                candidate_id=cand_id,
                snapshot_id=snapshot.snapshot_id,
                category="process",
                name=p.name,
                target_path=target_path,
                cmdline=p.cmdline,
                sha256=sha256,
                size_bytes=size_bytes,
                discovery_source="snapshot_collector",
                heuristics_matched=p.suspicious_reasons,
                priority_score=score,
                status=CandidateStatus.DISCOVERED,
                metadata={"pid": p.pid, "user": p.user, "integrity_level": p.integrity_level}
            ))

    # 2. Suspicious Persistence
    for per in snapshot.persistence:
        if per.is_suspicious:
            target_path = per.file_path or _extract_executable_path(per.command)
            sha256 = _calculate_file_sha256(target_path) if target_path else None
            size_bytes = _get_file_size(target_path) if target_path else None

            dedup_key = f"persistence|{per.location.lower()}|{per.name.lower()}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            score = calculate_candidate_priority(
                category="persistence",
                reasons=per.suspicious_reasons,
                path=target_path,
                cmdline=per.command,
                is_diff=False
            )

            cand_id = f"cand_persist_{uuid.uuid4().hex[:8]}"
            candidates.append(SuspiciousCandidate(
                candidate_id=cand_id,
                snapshot_id=snapshot.snapshot_id,
                category="persistence",
                name=per.name,
                target_path=target_path,
                cmdline=per.command,
                sha256=sha256,
                size_bytes=size_bytes,
                discovery_source="snapshot_collector",
                heuristics_matched=per.suspicious_reasons,
                priority_score=score,
                status=CandidateStatus.DISCOVERED,
                metadata={"location": per.location, "type": per.type}
            ))

    # 3. Suspicious Services
    for s in snapshot.services:
        if s.is_suspicious:
            target_path = _extract_executable_path(s.binary_path or "")
            sha256 = _calculate_file_sha256(target_path) if target_path else None
            size_bytes = _get_file_size(target_path) if target_path else None

            dedup_key = f"service|{s.name.lower()}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            score = calculate_candidate_priority(
                category="service",
                reasons=s.suspicious_reasons,
                path=target_path,
                cmdline=s.binary_path,
                is_diff=False
            )

            cand_id = f"cand_svc_{uuid.uuid4().hex[:8]}"
            candidates.append(SuspiciousCandidate(
                candidate_id=cand_id,
                snapshot_id=snapshot.snapshot_id,
                category="service",
                name=s.name,
                target_path=target_path,
                cmdline=s.binary_path,
                sha256=sha256,
                size_bytes=size_bytes,
                discovery_source="snapshot_collector",
                heuristics_matched=s.suspicious_reasons,
                priority_score=score,
                status=CandidateStatus.DISCOVERED,
                metadata={"start_mode": s.start_mode, "display_name": s.display_name}
            ))

    # 4. Suspicious Scheduled Tasks
    for t in snapshot.scheduled_tasks:
        if t.is_suspicious:
            target_path = _extract_executable_path(t.action or "")
            sha256 = _calculate_file_sha256(target_path) if target_path else None
            size_bytes = _get_file_size(target_path) if target_path else None

            dedup_key = f"task|{t.path.lower()}|{t.name.lower()}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            score = calculate_candidate_priority(
                category="scheduled_task",
                reasons=t.suspicious_reasons,
                path=target_path,
                cmdline=t.action,
                is_diff=False
            )

            cand_id = f"cand_task_{uuid.uuid4().hex[:8]}"
            candidates.append(SuspiciousCandidate(
                candidate_id=cand_id,
                snapshot_id=snapshot.snapshot_id,
                category="scheduled_task",
                name=t.name,
                target_path=target_path,
                cmdline=t.action,
                sha256=sha256,
                size_bytes=size_bytes,
                discovery_source="snapshot_collector",
                heuristics_matched=t.suspicious_reasons,
                priority_score=score,
                status=CandidateStatus.DISCOVERED,
                metadata={"path": t.path, "state": t.state, "author": t.author}
            ))

    # 5. Suspicious Files (Downloads, Temp, AppData)
    for f in snapshot.files:
        if f.is_suspicious:
            dedup_key = f"file|{f.path.lower()}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            sha256 = f.sha256 or _calculate_file_sha256(f.path)
            size_bytes = f.size_bytes or _get_file_size(f.path)

            score = calculate_candidate_priority(
                category="file",
                reasons=f.suspicious_reasons,
                path=f.path,
                cmdline=None,
                is_diff=False
            )

            cand_id = f"cand_file_{uuid.uuid4().hex[:8]}"
            candidates.append(SuspiciousCandidate(
                candidate_id=cand_id,
                snapshot_id=snapshot.snapshot_id,
                category="file",
                name=f.name,
                target_path=f.path,
                cmdline=None,
                sha256=sha256,
                size_bytes=size_bytes,
                discovery_source="snapshot_collector",
                heuristics_matched=f.suspicious_reasons,
                priority_score=score,
                status=CandidateStatus.DISCOVERED,
                metadata={"category": f.category, "extension": f.extension}
            ))

    # 6. Suspicious Network Sockets
    for n in snapshot.network:
        if n.is_suspicious:
            dedup_key = f"net|{n.proto}|{n.local_addr}:{n.local_port}|{n.remote_addr}:{n.remote_port}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            score = calculate_candidate_priority(
                category="network",
                reasons=n.suspicious_reasons,
                path=n.process_name,
                cmdline=f"{n.proto} {n.local_addr}:{n.local_port} -> {n.remote_addr}:{n.remote_port}",
                is_diff=False
            )

            cand_id = f"cand_net_{uuid.uuid4().hex[:8]}"
            candidates.append(SuspiciousCandidate(
                candidate_id=cand_id,
                snapshot_id=snapshot.snapshot_id,
                category="network",
                name=n.process_name or f"PID {n.pid}",
                target_path=None,
                cmdline=f"{n.proto} {n.local_addr}:{n.local_port} -> {n.remote_addr}:{n.remote_port}",
                sha256=None,
                size_bytes=None,
                discovery_source="snapshot_collector",
                heuristics_matched=n.suspicious_reasons,
                priority_score=score,
                status=CandidateStatus.DISCOVERED,
                metadata={"pid": n.pid, "state": n.state, "local": f"{n.local_addr}:{n.local_port}"}
            ))

    # Sort descending by priority score
    candidates.sort(key=lambda c: c.priority_score, reverse=True)
    return candidates


def detect_candidates_from_diff(
    diff: SecurityDiffResult,
    target_snapshot: SecuritySnapshot
) -> List[SuspiciousCandidate]:
    """
    Inspects security-relevant changes from a SecurityDiffResult and converts them
    into prioritized investigation candidates.
    """
    candidates: List[SuspiciousCandidate] = []
    seen_keys = set()

    for item in diff.security_relevant_changes:
        details = item.details or {}
        target_val = item.target_value or {}

        # Resolve path and cmdline
        path = details.get("path") or target_val.get("path")
        cmdline = details.get("cmdline") or details.get("command") or target_val.get("cmdline") or target_val.get("command")
        if not path and cmdline:
            path = _extract_executable_path(cmdline)

        sha256 = details.get("sha256") or target_val.get("sha256")
        if not sha256 and path:
            sha256 = _calculate_file_sha256(path)

        size_bytes = details.get("size_bytes") or target_val.get("size_bytes")
        if not size_bytes and path:
            size_bytes = _get_file_size(path)

        dedup_key = f"{item.category}|{item.name.lower()}|{path or ''}|{cmdline or ''}"
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        score = calculate_candidate_priority(
            category=item.category,
            reasons=item.reasons,
            path=path,
            cmdline=cmdline,
            is_diff=True
        )

        cand_id = f"cand_diff_{uuid.uuid4().hex[:8]}"
        candidates.append(SuspiciousCandidate(
            candidate_id=cand_id,
            snapshot_id=diff.target_snapshot_id,
            category=item.category,
            name=item.name,
            target_path=path,
            cmdline=cmdline,
            sha256=sha256,
            size_bytes=size_bytes,
            discovery_source="security_diff",
            heuristics_matched=item.reasons,
            priority_score=score,
            status=CandidateStatus.DISCOVERED,
            metadata={
                "diff_id": diff.diff_id,
                "change_type": item.change_type,
                "risk_level": item.risk_level
            }
        ))

    candidates.sort(key=lambda c: c.priority_score, reverse=True)
    return candidates
