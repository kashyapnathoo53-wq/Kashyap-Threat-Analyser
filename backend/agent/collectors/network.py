import sys
import time
import subprocess
import re
from typing import List, Tuple, Dict, Optional
from agent.models.snapshot import NetworkConnectionItem, CollectorReport
from agent.security.suspicious_items import evaluate_network_heuristics

def collect_network_connections(process_map: Optional[Dict[int, str]] = None) -> Tuple[List[NetworkConnectionItem], CollectorReport]:
    t0 = time.time()
    collector_name = "network"
    items: List[NetworkConnectionItem] = []
    error_msg = None
    status = "SUCCESS"

    if sys.platform != "win32":
        duration = round((time.time() - t0) * 1000, 2)
        return (items, CollectorReport(collector=collector_name, status="SUCCESS", item_count=0, duration_ms=duration))

    proc_dict = process_map or {}

    try:
        # Run netstat -ano to get all active connections with PIDs
        res = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, errors="ignore", timeout=6)
        if res.returncode == 0 and res.stdout.strip():
            for line in res.stdout.splitlines():
                parts = line.strip().split()
                if not parts:
                    continue

                proto = parts[0].upper()
                if proto not in ["TCP", "UDP"]:
                    continue

                if proto == "TCP" and len(parts) >= 5:
                    local_raw = parts[1]
                    remote_raw = parts[2]
                    state = parts[3]
                    try:
                        pid = int(parts[4])
                    except ValueError:
                        continue

                    # Parse local ip and port
                    if ":" in local_raw:
                        l_ip, l_port_str = local_raw.rsplit(":", 1)
                        try:
                            l_port = int(l_port_str)
                        except ValueError:
                            l_port = 0
                    else:
                        l_ip = local_raw
                        l_port = 0

                    # Parse remote ip and port
                    r_ip = None
                    r_port = None
                    if ":" in remote_raw:
                        r_ip_cand, r_port_cand = remote_raw.rsplit(":", 1)
                        if r_ip_cand not in ["*", "0.0.0.0", "[::]"]:
                            r_ip = r_ip_cand
                        try:
                            r_port = int(r_port_cand)
                        except ValueError:
                            r_port = None

                    proc_name = proc_dict.get(pid, "Unknown")
                    is_sus, reasons = evaluate_network_heuristics(r_ip or "", r_port or 0, proc_name)

                    items.append(NetworkConnectionItem(
                        proto="TCP",
                        local_addr=l_ip,
                        local_port=l_port,
                        remote_addr=r_ip,
                        remote_port=r_port,
                        state=state,
                        pid=pid,
                        process_name=proc_name if proc_name != "Unknown" else None,
                        is_suspicious=is_sus,
                        suspicious_reasons=reasons
                    ))

                elif proto == "UDP" and len(parts) >= 4:
                    local_raw = parts[1]
                    try:
                        pid = int(parts[-1])
                    except ValueError:
                        continue

                    if ":" in local_raw:
                        l_ip, l_port_str = local_raw.rsplit(":", 1)
                        try:
                            l_port = int(l_port_str)
                        except ValueError:
                            l_port = 0
                    else:
                        l_ip = local_raw
                        l_port = 0

                    proc_name = proc_dict.get(pid, "Unknown")

                    items.append(NetworkConnectionItem(
                        proto="UDP",
                        local_addr=l_ip,
                        local_port=l_port,
                        state="LISTENING",
                        pid=pid,
                        process_name=proc_name if proc_name != "Unknown" else None,
                        is_suspicious=False,
                        suspicious_reasons=[]
                    ))

    except Exception as e:
        status = "ERROR"
        error_msg = f"Network socket collection error: {str(e)}"

    duration_ms = round((time.time() - t0) * 1000, 2)
    report = CollectorReport(
        collector=collector_name,
        status=status,
        item_count=len(items),
        duration_ms=duration_ms,
        error=error_msg
    )
    return items, report
