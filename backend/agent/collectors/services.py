import sys
import time
from typing import List, Tuple, Dict
from agent.models.snapshot import ServiceItem, CollectorReport
from agent.security.suspicious_items import evaluate_service_heuristics

def collect_services() -> Tuple[List[ServiceItem], CollectorReport]:
    t0 = time.time()
    collector_name = "services"
    items: List[ServiceItem] = []
    error_msg = None
    status = "SUCCESS"

    if sys.platform != "win32":
        duration = round((time.time() - t0) * 1000, 2)
        return (items, CollectorReport(collector=collector_name, status="SUCCESS", item_count=0, duration_ms=duration))

    import winreg

    # Map Windows SERVICE_START_TYPE integers to human-readable strings
    START_MODE_MAP = {
        0: "Boot",
        1: "System",
        2: "Auto",
        3: "Manual",
        4: "Disabled"
    }

    try:
        services_key_path = r"SYSTEM\CurrentControlSet\Services"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, services_key_path, 0, winreg.KEY_READ) as s_key:
            num_subkeys = winreg.QueryInfoKey(s_key)[0]

            for i in range(num_subkeys):
                try:
                    svc_name = winreg.EnumKey(s_key, i)
                    with winreg.OpenKey(s_key, svc_name, 0, winreg.KEY_READ) as svc_sub:
                        # Extract ImagePath
                        image_path = None
                        try:
                            val, _ = winreg.QueryValueEx(svc_sub, "ImagePath")
                            image_path = str(val).strip()
                        except FileNotFoundError:
                            pass

                        # If service has no ImagePath, it's typically a driver without binary or container
                        if not image_path:
                            continue

                        # Extract DisplayName
                        display_name = svc_name
                        try:
                            dn, _ = winreg.QueryValueEx(svc_sub, "DisplayName")
                            if dn:
                                display_name = str(dn).strip()
                        except FileNotFoundError:
                            pass

                        # Extract Start mode
                        start_mode = "Unknown"
                        try:
                            sm, _ = winreg.QueryValueEx(svc_sub, "Start")
                            start_mode = START_MODE_MAP.get(sm, "Unknown")
                        except FileNotFoundError:
                            pass

                        is_sus, reasons = evaluate_service_heuristics(svc_name, display_name, image_path)

                        items.append(ServiceItem(
                            name=svc_name,
                            display_name=display_name,
                            status="CONFIGURED",
                            start_mode=start_mode,
                            binary_path=image_path,
                            is_suspicious=is_sus,
                            suspicious_reasons=reasons
                        ))
                except Exception:
                    continue

    except Exception as e:
        status = "ERROR"
        error_msg = f"Failed to enumerate Windows services: {str(e)}"

    duration_ms = round((time.time() - t0) * 1000, 2)
    report = CollectorReport(
        collector=collector_name,
        status=status,
        item_count=len(items),
        duration_ms=duration_ms,
        error=error_msg
    )
    return items, report
