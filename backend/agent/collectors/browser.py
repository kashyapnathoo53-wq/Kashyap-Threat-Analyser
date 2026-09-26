import os
import sys
import time
from pathlib import Path
from typing import List, Tuple
from agent.models.snapshot import BrowserInfo, CollectorReport

def collect_browser_info() -> Tuple[List[BrowserInfo], CollectorReport]:
    t0 = time.time()
    collector_name = "browser"
    items: List[BrowserInfo] = []
    error_msg = None
    status = "SUCCESS"

    if sys.platform != "win32":
        duration = round((time.time() - t0) * 1000, 2)
        return (items, CollectorReport(collector=collector_name, status="SUCCESS", item_count=0, duration_ms=duration))

    import winreg

    # Determine default browser from Windows registry
    default_browser_progid = ""
    try:
        choice_key = r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, choice_key, 0, winreg.KEY_READ) as k:
            val, _ = winreg.QueryValueEx(k, "ProgId")
            default_browser_progid = str(val).lower()
    except Exception:
        pass

    local_appdata = os.environ.get("LOCALAPPDATA", "")
    roaming_appdata = os.environ.get("APPDATA", "")

    # Browser definitions
    browsers_to_check = [
        {
            "name": "Google Chrome",
            "progid_match": "chrome",
            "profile_dir": Path(local_appdata) / "Google" / "Chrome" / "User Data" if local_appdata else None,
            "ext_subdir": "Default/Extensions"
        },
        {
            "name": "Microsoft Edge",
            "progid_match": "msedge",
            "profile_dir": Path(local_appdata) / "Microsoft" / "Edge" / "User Data" if local_appdata else None,
            "ext_subdir": "Default/Extensions"
        },
        {
            "name": "Brave Browser",
            "progid_match": "brave",
            "profile_dir": Path(local_appdata) / "BraveSoftware" / "Brave-Browser" / "User Data" if local_appdata else None,
            "ext_subdir": "Default/Extensions"
        },
        {
            "name": "Mozilla Firefox",
            "progid_match": "firefox",
            "profile_dir": Path(roaming_appdata) / "Mozilla" / "Firefox" / "Profiles" if roaming_appdata else None,
            "ext_subdir": ""
        }
    ]

    for b in browsers_to_check:
        try:
            p_dir = b["profile_dir"]
            is_installed = p_dir is not None and p_dir.exists()
            is_default = b["progid_match"] in default_browser_progid

            profile_paths = []
            extensions_found = 0

            if is_installed and p_dir:
                profile_paths.append(str(p_dir))
                
                # Check for Extensions directory in Chromium browsers
                if b["ext_subdir"]:
                    ext_path = p_dir / b["ext_subdir"].replace("/", "\\")
                    if ext_path.exists() and ext_path.is_dir():
                        try:
                            ext_dirs = [d for d in ext_path.iterdir() if d.is_dir()]
                            extensions_found = len(ext_dirs)
                        except Exception:
                            pass

            if is_installed or is_default:
                items.append(BrowserInfo(
                    name=b["name"],
                    is_installed=is_installed,
                    is_default=is_default,
                    profile_paths=profile_paths,
                    extensions_found=extensions_found,
                    suspicious_extensions=[]
                ))
        except Exception:
            pass

    duration_ms = round((time.time() - t0) * 1000, 2)
    report = CollectorReport(
        collector=collector_name,
        status=status,
        item_count=len(items),
        duration_ms=duration_ms,
        error=error_msg
    )
    return items, report
