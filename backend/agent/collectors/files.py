import os
import sys
import time
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Set, Optional
from agent.models.snapshot import FileItem, CollectorReport
from agent.security.suspicious_items import evaluate_file_heuristics

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".pif", ".com", ".cpl", ".sys",
    ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".py",
    ".docm", ".xlsm", ".iso", ".img"
}

def compute_file_sha256(path: str, max_size_bytes: int = 26214400) -> Optional[str]:
    try:
        if not os.path.isfile(path):
            return None
        size = os.path.getsize(path)
        if size > max_size_bytes or size == 0:
            return None

        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def collect_security_files(referenced_paths: Optional[List[str]] = None) -> Tuple[List[FileItem], CollectorReport]:
    t0 = time.time()
    collector_name = "files"
    items: List[FileItem] = []
    seen_paths: Set[str] = set()
    error_msg = None
    status = "SUCCESS"

    if sys.platform != "win32":
        duration = round((time.time() - t0) * 1000, 2)
        return (items, CollectorReport(collector=collector_name, status="SUCCESS", item_count=0, duration_ms=duration))

    # Helper function to process a single file safely
    def process_file_candidate(p: Path, category: str):
        p_str = str(p)
        if p_str in seen_paths:
            return
        seen_paths.add(p_str)

        try:
            st = p.stat()
            size = st.st_size
            ext = p.suffix.lower()

            # Format timestamps
            ctime_iso = datetime.fromtimestamp(st.st_ctime).isoformat() + "Z"
            mtime_iso = datetime.fromtimestamp(st.st_mtime).isoformat() + "Z"

            # Compute hash for binaries and scripts
            sha256 = None
            if ext in SUSPICIOUS_EXTENSIONS and size < 26214400:
                sha256 = compute_file_sha256(p_str)

            is_sus, reasons = evaluate_file_heuristics(p.name, p_str, size)

            items.append(FileItem(
                path=p_str,
                name=p.name,
                size_bytes=size,
                category=category,
                extension=ext,
                created_time=ctime_iso,
                modified_time=mtime_iso,
                sha256=sha256,
                is_suspicious=is_sus,
                suspicious_reasons=reasons
            ))
        except (PermissionError, FileNotFoundError):
            pass
        except Exception:
            pass

    # 1. Inspect referenced files from running processes
    if referenced_paths:
        for ref in referenced_paths:
            if ref and os.path.isfile(ref):
                process_file_candidate(Path(ref), "ProcessReference")

    # 2. Targeted Security Locations
    target_locations = []

    # Downloads
    downloads_dir = Path.home() / "Downloads"
    if downloads_dir.exists():
        target_locations.append((downloads_dir, "Downloads", 1))

    # User Temp
    user_temp = os.environ.get("TEMP") or os.environ.get("TMP")
    if user_temp and Path(user_temp).exists():
        target_locations.append((Path(user_temp), "Temp", 2))

    # System Temp
    sys_temp = Path("C:\\Windows\\Temp")
    if sys_temp.exists():
        target_locations.append((sys_temp, "Temp", 1))

    # Startup Folders
    appdata = os.environ.get("APPDATA")
    if appdata:
        u_startup = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        if u_startup.exists():
            target_locations.append((u_startup, "Startup", 1))

    # AppData Volatile Roots (Local & Roaming)
    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata and Path(local_appdata).exists():
        target_locations.append((Path(local_appdata), "AppData", 1))
        # Also check Local\Programs
        loc_prog = Path(local_appdata) / "Programs"
        if loc_prog.exists():
            target_locations.append((loc_prog, "AppData", 2))

    # Scan target locations with bounded depth and file count
    for base_dir, cat, max_depth in target_locations:
        try:
            file_count_in_loc = 0
            for root, dirs, files in os.walk(str(base_dir)):
                # Calculate current depth relative to base_dir
                rel_parts = Path(root).relative_to(base_dir).parts
                if len(rel_parts) > max_depth:
                    dirs.clear()
                    continue

                for f in files:
                    ext = Path(f).suffix.lower()
                    if ext in SUSPICIOUS_EXTENSIONS or cat in ["Temp", "Startup"]:
                        process_file_candidate(Path(root) / f, cat)
                        file_count_in_loc += 1
                        if file_count_in_loc >= 100:
                            break

                if file_count_in_loc >= 100:
                    break
        except Exception as e:
            error_msg = f"Error scanning {base_dir}: {str(e)}"

    duration_ms = round((time.time() - t0) * 1000, 2)
    report = CollectorReport(
        collector=collector_name,
        status=status,
        item_count=len(items),
        duration_ms=duration_ms,
        error=error_msg
    )
    return items, report
