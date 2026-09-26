import sys
import time
import subprocess
import csv
import io
from typing import List, Tuple
from agent.models.snapshot import ScheduledTaskItem, CollectorReport
from agent.security.suspicious_items import evaluate_scheduled_task_heuristics

def collect_scheduled_tasks() -> Tuple[List[ScheduledTaskItem], CollectorReport]:
    t0 = time.time()
    collector_name = "scheduled_tasks"
    items: List[ScheduledTaskItem] = []
    error_msg = None
    status = "SUCCESS"

    if sys.platform != "win32":
        duration = round((time.time() - t0) * 1000, 2)
        return (items, CollectorReport(collector=collector_name, status="SUCCESS", item_count=0, duration_ms=duration))

    try:
        # Run schtasks with verbose CSV output
        proc = subprocess.run(
            ["schtasks", "/query", "/FO", "CSV", "/V"],
            capture_output=True,
            text=True,
            errors="ignore",
            timeout=8
        )

        if proc.returncode == 0 and proc.stdout.strip():
            reader = csv.reader(io.StringIO(proc.stdout))
            header = next(reader, None)
            
            # Find column indices dynamically
            col_map = {}
            if header:
                for idx, h in enumerate(header):
                    col_map[h.strip().lower()] = idx

            name_idx = col_map.get("taskname", 1)
            status_idx = col_map.get("status", 3)
            author_idx = col_map.get("author", 7)
            action_idx = col_map.get("task to run", 8)

            for row in reader:
                if len(row) > max(name_idx, status_idx, action_idx):
                    full_name = row[name_idx].strip()
                    if not full_name:
                        continue

                    # Extract path and base name
                    if "\\" in full_name:
                        parts = full_name.rsplit("\\", 1)
                        task_path = parts[0] or "\\"
                        task_name = parts[1]
                    else:
                        task_path = "\\"
                        task_name = full_name

                    t_status = row[status_idx].strip() if len(row) > status_idx else "Unknown"
                    t_author = row[author_idx].strip() if len(row) > author_idx else None
                    t_action = row[action_idx].strip() if len(row) > action_idx else None

                    is_sus, reasons = evaluate_scheduled_task_heuristics(task_name, task_path, t_action or "")

                    items.append(ScheduledTaskItem(
                        name=task_name,
                        path=task_path,
                        state=t_status,
                        action=t_action,
                        author=t_author if t_author != "N/A" else None,
                        is_suspicious=is_sus,
                        suspicious_reasons=reasons
                    ))

    except Exception as e:
        status = "PARTIAL" if items else "ERROR"
        error_msg = f"Scheduled tasks enumeration error: {str(e)}"

    # Fallback to non-verbose schtasks if verbose timed out or returned empty
    if not items:
        try:
            p_fallback = subprocess.run(["schtasks", "/query", "/FO", "CSV", "/NH"], capture_output=True, text=True, errors="ignore", timeout=4)
            if p_fallback.returncode == 0 and p_fallback.stdout.strip():
                reader = csv.reader(io.StringIO(p_fallback.stdout))
                for row in reader:
                    if len(row) >= 3:
                        full_name = row[0].strip()
                        st = row[2].strip()
                        is_sus, reasons = evaluate_scheduled_task_heuristics(full_name, full_name, "")
                        items.append(ScheduledTaskItem(
                            name=full_name.split("\\")[-1],
                            path=full_name,
                            state=st,
                            is_suspicious=is_sus,
                            suspicious_reasons=reasons
                        ))
                status = "SUCCESS"
                error_msg = None
        except Exception as e2:
            status = "ERROR"
            error_msg = f"Fallback tasks query failed: {str(e2)}"

    duration_ms = round((time.time() - t0) * 1000, 2)
    report = CollectorReport(
        collector=collector_name,
        status=status,
        item_count=len(items),
        duration_ms=duration_ms,
        error=error_msg
    )
    return items, report
