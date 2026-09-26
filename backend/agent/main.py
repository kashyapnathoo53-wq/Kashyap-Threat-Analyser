import os
import sys
import time
import socket
import platform
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional

# Ensure agent package can be imported regardless of execution working directory
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(current_dir)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from agent.models.snapshot import SecuritySnapshot, CollectorReport, SuspiciousSummaryItem
from agent.collectors.processes import collect_processes
from agent.collectors.persistence import collect_persistence
from agent.collectors.services import collect_services
from agent.collectors.scheduled_tasks import collect_scheduled_tasks
from agent.collectors.network import collect_network_connections
from agent.collectors.files import collect_security_files
from agent.collectors.browser import collect_browser_info
from agent.storage.snapshot_store import SnapshotStore
from agent.communication.protocol import read_native_message, send_native_message

AGENT_VERSION = "2.0.0"

def get_machine_id() -> str:
    """Extracts Windows MachineGuid or derives a deterministic host fingerprint."""
    if platform.system() == "Windows":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_READ) as k:
                guid, _ = winreg.QueryValueEx(k, "MachineGuid")
                if guid:
                    return str(guid).strip()
        except Exception:
            pass
    import hashlib
    raw = f"{socket.gethostname()}-{platform.node()}-{platform.machine()}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]

def get_system_metadata() -> Dict[str, Any]:
    machine_id = get_machine_id()
    os_str = f"{platform.system()} {platform.release()} ({platform.version()})"
    return {
        "hostname": socket.gethostname(),
        "machine_id": machine_id,
        "os": os_str,
        "os_version": os_str,
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "agent_version": AGENT_VERSION,
        "current_user": os.environ.get("USERNAME", "Unknown"),
    }

def run_local_scan(save_to_store: bool = True, storage_dir: Optional[str] = None) -> SecuritySnapshot:
    """
    Executes a complete read-only local security scan across all host collectors
    and builds an internally normalized Security Snapshot.
    """
    t_start = time.time()
    now_utc = datetime.now(timezone.utc)
    snapshot_id = f"snap_{now_utc.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    collector_reports: Dict[str, CollectorReport] = {}

    from concurrent.futures import ThreadPoolExecutor

    # Execute Phase 1 collectors concurrently
    with ThreadPoolExecutor(max_workers=5) as executor:
        f_proc = executor.submit(collect_processes)
        f_persist = executor.submit(collect_persistence)
        f_services = executor.submit(collect_services)
        f_tasks = executor.submit(collect_scheduled_tasks)
        f_browser = executor.submit(collect_browser_info)

        processes, rep_proc = f_proc.result()
        persistence, rep_persist = f_persist.result()
        services, rep_services = f_services.result()
        tasks, rep_tasks = f_tasks.result()
        browser_info, rep_browser = f_browser.result()

    collector_reports["processes"] = rep_proc
    collector_reports["persistence"] = rep_persist
    collector_reports["services"] = rep_services
    collector_reports["scheduled_tasks"] = rep_tasks
    collector_reports["browser"] = rep_browser

    # Build process map (PID -> Name) and referenced executable paths for downstream correlation
    proc_map = {p.pid: p.name for p in processes}
    proc_paths = [p.path for p in processes if p.path]

    # Execute Phase 2 collectors (dependent on process paths) concurrently
    with ThreadPoolExecutor(max_workers=2) as executor:
        f_network = executor.submit(collect_network_connections, proc_map)
        f_files = executor.submit(collect_security_files, proc_paths)

        network, rep_network = f_network.result()
        files, rep_files = f_files.result()

    collector_reports["network"] = rep_network
    collector_reports["files"] = rep_files

    # Pre-screened unified suspicious items consolidation
    suspicious_items: List[SuspiciousSummaryItem] = []

    for p in processes:
        if p.is_suspicious:
            suspicious_items.append(SuspiciousSummaryItem(
                category="process",
                name=p.name,
                target=p.cmdline or p.path or f"PID {p.pid}",
                reasons=p.suspicious_reasons,
                severity="HIGH",
                details={"pid": p.pid, "path": p.path, "cmdline": p.cmdline, "user": p.user}
            ))

    for per in persistence:
        if per.is_suspicious:
            suspicious_items.append(SuspiciousSummaryItem(
                category="persistence",
                name=per.name,
                target=per.command,
                reasons=per.suspicious_reasons,
                severity="HIGH",
                details={"location": per.location, "type": per.type, "file_path": per.file_path}
            ))

    for s in services:
        if s.is_suspicious:
            suspicious_items.append(SuspiciousSummaryItem(
                category="service",
                name=s.name,
                target=s.binary_path,
                reasons=s.suspicious_reasons,
                severity="MEDIUM",
                details={"display_name": s.display_name, "start_mode": s.start_mode}
            ))

    for t in tasks:
        if t.is_suspicious:
            suspicious_items.append(SuspiciousSummaryItem(
                category="scheduled_task",
                name=t.name,
                target=t.action,
                reasons=t.suspicious_reasons,
                severity="MEDIUM",
                details={"path": t.path, "state": t.state, "author": t.author}
            ))

    for n in network:
        if n.is_suspicious:
            suspicious_items.append(SuspiciousSummaryItem(
                category="network",
                name=n.process_name or f"PID {n.pid}",
                target=f"{n.remote_addr}:{n.remote_port}",
                reasons=n.suspicious_reasons,
                severity="HIGH",
                details={"local": f"{n.local_addr}:{n.local_port}", "proto": n.proto, "pid": n.pid}
            ))

    for f in files:
        if f.is_suspicious:
            suspicious_items.append(SuspiciousSummaryItem(
                category="file",
                name=f.name,
                target=f.path,
                reasons=f.suspicious_reasons,
                severity="CRITICAL" if any("double" in r.lower() for r in f.suspicious_reasons) else "HIGH",
                details={"category": f.category, "size_bytes": f.size_bytes, "sha256": f.sha256}
            ))

    # Compute Summary Statistics
    suspicious_procs = sum(1 for p in processes if p.is_suspicious)
    suspicious_persist = sum(1 for p in persistence if p.is_suspicious)
    suspicious_services = sum(1 for s in services if s.is_suspicious)
    suspicious_tasks = sum(1 for t in tasks if t.is_suspicious)
    suspicious_network = sum(1 for n in network if n.is_suspicious)
    suspicious_files = sum(1 for f in files if f.is_suspicious)
    scan_duration = round((time.time() - t_start) * 1000, 2)

    summary = {
        "total_processes": len(processes),
        "suspicious_processes": suspicious_procs,
        "total_persistence": len(persistence),
        "suspicious_persistence": suspicious_persist,
        "total_services": len(services),
        "suspicious_services": suspicious_services,
        "total_scheduled_tasks": len(tasks),
        "suspicious_scheduled_tasks": suspicious_tasks,
        "total_network_connections": len(network),
        "suspicious_network_connections": suspicious_network,
        "total_files_scanned": len(files),
        "suspicious_files": suspicious_files,
        "total_browsers_detected": len(browser_info),
        "total_suspicious_items": len(suspicious_items),
        "scan_duration_ms": scan_duration
    }

    sys_meta = get_system_metadata()
    snapshot_metadata = {
        "schema_version": "2.0.0",
        "agent_version": AGENT_VERSION,
        "scan_duration_ms": scan_duration,
        "generated_at": now_utc.isoformat(),
        "host_id": sys_meta["machine_id"],
        "total_items_scanned": (
            len(processes) + len(persistence) + len(services) +
            len(tasks) + len(network) + len(files) + len(browser_info)
        ),
        "total_suspicious_items": len(suspicious_items),
        "item_counts": {
            "processes": len(processes),
            "persistence": len(persistence),
            "services": len(services),
            "scheduled_tasks": len(tasks),
            "network_connections": len(network),
            "scanned_files": len(files),
            "browser_info": len(browser_info),
        },
        "collectors_summary": {k: v.status for k, v in collector_reports.items()}
    }

    snapshot = SecuritySnapshot(
        snapshot_id=snapshot_id,
        schema_version="2.0.0",
        timestamp=now_utc.isoformat(),
        host_id=sys_meta["machine_id"],
        os_version=sys_meta["os_version"],
        system_info=sys_meta,
        summary=summary,
        snapshot_metadata=snapshot_metadata,
        collector_reports=collector_reports,
        processes=processes,
        persistence=persistence,
        services=services,
        scheduled_tasks=tasks,
        network=network,
        files=files,
        browser=browser_info,
        suspicious_items=suspicious_items,
    )

    if save_to_store:
        store = SnapshotStore(storage_dir)
        store.save_snapshot(snapshot)

    return snapshot


def run_native_messaging_host():
    """Loops reading from standard input for Chrome/Edge Native Messaging commands."""
    store = SnapshotStore()
    while True:
        try:
            msg = read_native_message()
            if not msg:
                break

            action = msg.get("action")
            if action == "SCAN":
                snap = run_local_scan(save_to_store=True)
                send_native_message({
                    "status": "success",
                    "snapshot_id": snap.snapshot_id,
                    "summary": snap.summary
                })
            elif action == "GET_LATEST":
                snap = store.get_latest_snapshot()
                if snap:
                    send_native_message({"status": "success", "snapshot": snap.model_dump()})
                else:
                    send_native_message({"status": "empty", "message": "No snapshots recorded yet"})
            elif action == "PING":
                send_native_message({"status": "pong", "agent_version": AGENT_VERSION})
            else:
                send_native_message({"status": "error", "message": f"Unknown action: {action}"})
        except Exception as e:
            send_native_message({"status": "error", "message": str(e)})
            break

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Pasha Windows Local Agent - Read-Only Security Inspection")
    parser.add_argument("--json", action="store_true", help="Output full JSON snapshot to stdout")
    parser.add_argument("--no-save", action="store_true", help="Do not persist snapshot to disk")
    parser.add_argument("--native", action="store_true", help="Run as browser Native Messaging host")
    args = parser.parse_args()

    if args.native:
        run_native_messaging_host()
        return

    print("=" * 65)
    print("  PASHA LOCAL AGENT 2.0 — WINDOWS READ-ONLY SECURITY SCANNER")
    print("=" * 65)
    print("[*] Initiating non-intrusive host telemetry collection...")

    snap = run_local_scan(save_to_store=not args.no_save)

    if args.json:
        print(snap.model_dump_json(indent=2))
        return

    sys_info = snap.system_info
    summ = snap.summary

    print(f"\n[+] Snapshot Created: {snap.snapshot_id} (Duration: {summ['scan_duration_ms']}ms)")
    print(f"    Host: {sys_info.get('hostname')} | OS: {sys_info.get('os')} | User: {sys_info.get('current_user')}")
    print("\n--- COLLECTOR BREAKDOWN ---")
    for c_name, report in snap.collector_reports.items():
        err_str = f" (Error: {report.error})" if report.error else ""
        print(f"  • {c_name:<16}: {report.item_count:>4} items collected in {report.duration_ms:>6.1f}ms [{report.status}]{err_str}")

    print("\n--- SECURITY FINDINGS SUMMARY ---")
    print(f"  • Running Processes          : {summ['total_processes']:>4} (Suspicious: {summ['suspicious_processes']})")
    print(f"  • Persistence Mechanisms     : {summ['total_persistence']:>4} (Suspicious: {summ['suspicious_persistence']})")
    print(f"  • Windows Services           : {summ['total_services']:>4} (Suspicious: {summ['suspicious_services']})")
    print(f"  • Scheduled Tasks            : {summ['total_scheduled_tasks']:>4} (Suspicious: {summ['suspicious_scheduled_tasks']})")
    print(f"  • Active Network Connections : {summ['total_network_connections']:>4} (Suspicious: {summ['suspicious_network_connections']})")
    print(f"  • Volatile Security Files    : {summ['total_files_scanned']:>4} (Suspicious: {summ['suspicious_files']})")
    print(f"  • Browsers Profiled          : {summ['total_browsers_detected']:>4}")
    print(f"  -------------------------------------------------------------")
    print(f"  • TOTAL ANOMALOUS CANDIDATES : {summ['total_suspicious_items']:>4}")
    print("=" * 65)

if __name__ == "__main__":
    main()
