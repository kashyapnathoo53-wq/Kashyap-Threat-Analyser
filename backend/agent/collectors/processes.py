import sys
import time
import subprocess
import json
import csv
import io
from typing import List, Tuple, Dict
from agent.models.snapshot import ProcessItem, CollectorReport
from agent.security.suspicious_items import evaluate_process_heuristics

def collect_processes() -> Tuple[List[ProcessItem], CollectorReport]:
    t0 = time.time()
    collector_name = "processes"
    items: List[ProcessItem] = []
    error_msg = None
    status = "SUCCESS"

    if sys.platform != "win32":
        # Cross-platform simulation / fallback for non-Windows dev environments
        duration = round((time.time() - t0) * 1000, 2)
        return ([
            ProcessItem(pid=4, name="System", ppid=0, path="ntoskrnl.exe", user="SYSTEM", integrity_level="SYSTEM"),
            ProcessItem(pid=1000, name="explorer.exe", ppid=4, path="C:\\Windows\\explorer.exe", user="User", integrity_level="Medium")
        ], CollectorReport(collector=collector_name, status="SUCCESS", item_count=2, duration_ms=duration))

    # Step 1: Collect User and Session info using fast native tasklist
    user_map: Dict[int, str] = {}
    try:
        tl_res = subprocess.run(
            ["tasklist", "/FO", "CSV", "/V"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if tl_res.returncode == 0 and tl_res.stdout.strip():
            reader = csv.reader(io.StringIO(tl_res.stdout))
            header = next(reader, None)
            for row in reader:
                if len(row) >= 7:
                    try:
                        pid_val = int(row[1].strip())
                        user_name = row[6].strip()
                        if user_name and user_name != "N/A":
                            user_map[pid_val] = user_name
                    except (ValueError, IndexError):
                        pass
    except Exception:
        # Non-fatal: continue even if tasklist /V fails
        pass

    # Step 2: Query detailed process hierarchy from CIM / WMI
    try:
        ps_cmd = (
            "Get-CimInstance Win32_Process | "
            "Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | "
            "ConvertTo-Json -Compress"
        )
        cim_res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=10
        )

        if cim_res.returncode == 0 and cim_res.stdout.strip():
            raw_output = cim_res.stdout.strip()
            data = json.loads(raw_output)
            if isinstance(data, dict):
                data = [data]

            for entry in data:
                pid = int(entry.get("ProcessId") or 0)
                ppid = int(entry.get("ParentProcessId") or 0) if entry.get("ParentProcessId") is not None else None
                name = str(entry.get("Name") or "Unknown")
                path = entry.get("ExecutablePath")
                cmdline = entry.get("CommandLine")
                user = user_map.get(pid, "N/A")

                # Estimate integrity level
                integrity = "Medium"
                if user in ["NT AUTHORITY\\SYSTEM", "SYSTEM"]:
                    integrity = "SYSTEM"
                elif user in ["NT AUTHORITY\\LOCAL SERVICE", "NT AUTHORITY\\NETWORK SERVICE"]:
                    integrity = "Low"

                is_sus, reasons = evaluate_process_heuristics(name, path or "", cmdline or "")

                items.append(ProcessItem(
                    pid=pid,
                    name=name,
                    ppid=ppid,
                    path=path,
                    cmdline=cmdline,
                    user=user,
                    integrity_level=integrity,
                    is_suspicious=is_sus,
                    suspicious_reasons=reasons
                ))

    except Exception as e:
        status = "PARTIAL" if items else "ERROR"
        error_msg = f"CIM Process query error: {str(e)}"

    # Step 3: Fallback to tasklist /FO CSV if CIM produced no items
    if not items:
        try:
            tl_simple = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=5)
            if tl_simple.returncode == 0 and tl_simple.stdout.strip():
                reader = csv.reader(io.StringIO(tl_simple.stdout))
                for row in reader:
                    if len(row) >= 2:
                        try:
                            p_name = row[0].strip()
                            p_pid = int(row[1].strip())
                            is_sus, reasons = evaluate_process_heuristics(p_name, "", "")
                            items.append(ProcessItem(
                                pid=p_pid,
                                name=p_name,
                                is_suspicious=is_sus,
                                suspicious_reasons=reasons
                            ))
                        except ValueError:
                            pass
                status = "SUCCESS"
                error_msg = None
        except Exception as e2:
            status = "ERROR"
            error_msg = f"Tasklist fallback failed: {str(e2)}"

    duration_ms = round((time.time() - t0) * 1000, 2)
    report = CollectorReport(
        collector=collector_name,
        status=status,
        item_count=len(items),
        duration_ms=duration_ms,
        error=error_msg
    )
    return items, report
